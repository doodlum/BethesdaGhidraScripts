"""Cross-version vtable slot matcher.

Given a reference BinaryLayout (the canonical version whose slot indices
match CommonLib header comments) and a target BinaryLayout (some other
binary version), produces a "shift map" telling the build-time patcher
where each reference slot lives in the target binary.

Matching strategy, per class:

  1. **Exact name match** -- if the same function name appears at slot X
     in ref and slot Y in target, ref[X] -> target[Y].  Strongest signal
     and handles the common case where PDB symbols are available.

  2. **Fingerprint match** -- if a ref slot's function fingerprint matches
     a target slot's fingerprint (Ghidra-style masked byte pattern), pair
     them.  Catches slots that exist in both binaries but were renamed
     or never named in one of them.

  3. **Anything left in target with no ref match** -- emitted as a
     "target-only slot": the patcher will add a placeholder field like
     `__<version>_only_0xXX` so the struct overlay covers it.

  4. **Anything left in ref with no target match** -- "removed slot":
     the patcher will drop it from the per-version struct.

Output is a ``ClassShiftMap`` per class, packaged in a ``ShiftMap``.

The matcher is intentionally conservative: when fingerprints don't
uniquely identify a slot, prefer "unmatched" over a guess.  Anchor
verification (see ``anchor_verifier.py``) catches anything the matcher
misses.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from vtable_layout import BinaryLayout, ClassVtable, SlotEntry


@dataclass
class ClassShiftMap:
    """How one class's slots map from reference -> target binary."""
    class_name: str
    ref_to_target: Dict[int, int] = field(default_factory=dict)  # ref_slot -> target_slot
    unmatched_ref_slots: List[int] = field(default_factory=list)  # in ref, missing in target
    target_only_slots: List[Tuple[int, SlotEntry]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class ShiftMap:
    """Full shift map for one (reference, target) binary pair."""
    reference_label: str
    target_label: str
    classes: Dict[str, ClassShiftMap] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            'reference': self.reference_label,
            'target': self.target_label,
            'classes': {
                cls: {
                    'ref_to_target': {'0x{:X}'.format(k): '0x{:X}'.format(v)
                                       for k, v in m.ref_to_target.items()},
                    'unmatched_ref_slots': ['0x{:X}'.format(s) for s in m.unmatched_ref_slots],
                    'target_only_slots': [
                        {'slot': '0x{:X}'.format(s), 'func_name': e.func_name,
                         'func_addr': '0x{:X}'.format(e.func_addr)}
                        for s, e in m.target_only_slots
                    ],
                    'notes': m.notes,
                }
                for cls, m in sorted(self.classes.items())
            },
        }


def _normalize_fingerprint(fp: str) -> str:
    """Strip whitespace, uppercase hex, normalize question marks.

    Ghidra emits like '48 8B C4 ? ? ? ? 48'.  We compare as a single string
    so spaces aren't significant.
    """
    if not fp:
        return ''
    parts = fp.replace('\t', ' ').split()
    return ' '.join(p.upper() if p != '?' else '?' for p in parts)


def _fingerprints_match(a: str, b: str,
                          min_concrete_bytes: int = 6,
                          prefix_window: int = 24,
                          max_concrete_mismatches: int = 1) -> bool:
    """True if two function-prologue fingerprints are compatible.

    Bethesda patches sometimes rewrite function bodies (insert calls,
    change constants) while keeping the MSVC frame-setup prologue
    identical.  So we only compare the *prefix* of the two fingerprints
    (where the standard register-save/stack-alloc pattern lives) instead
    of the whole body, and tolerate up to ``max_concrete_mismatches``
    differing concrete bytes within that window to handle prologues
    that differ only in a register pick or an immediate value.

    Args:
      a, b: normalized fingerprint strings (space-separated hex bytes
            or ``?`` wildcards).
      min_concrete_bytes:  minimum number of non-wildcard bytes that
            must match between the two prefixes for the pair to be
            considered a hit.  Below this the signal is too weak.
      prefix_window: only inspect the first N bytes of each fingerprint.
            ~20-30 bytes covers the MSVC prologue (RBP save, stack
            sub, parameter spills) without reaching into the function
            body where patches tend to diverge.
      max_concrete_mismatches: allow this many concrete-vs-concrete
            differences within the prefix before declaring a mismatch.
            Set to 0 for strict, 1 to tolerate a single register/imm
            swap.
    """
    if not a or not b:
        return False
    pa = a.split()
    pb = b.split()
    # Restrict to the prefix window
    n = min(len(pa), len(pb), prefix_window)
    if n == 0:
        return False
    concrete_matches = 0
    concrete_mismatches = 0
    for i in range(n):
        ai, bi = pa[i], pb[i]
        if ai == '?' or bi == '?':
            continue  # wildcard slot, ignore
        if ai != bi:
            concrete_mismatches += 1
            if concrete_mismatches > max_concrete_mismatches:
                return False
        else:
            concrete_matches += 1
    return concrete_matches >= min_concrete_bytes


def _match_one_class(ref: ClassVtable, tgt: ClassVtable) -> ClassShiftMap:
    sm = ClassShiftMap(class_name=ref.class_name)

    # Stage 1: exact name match
    target_by_name: Dict[str, List[int]] = {}
    for slot, e in tgt.slots.items():
        if e.func_name:
            target_by_name.setdefault(e.func_name, []).append(slot)

    used_target_slots = set()
    for ref_slot in sorted(ref.slots):
        re_ = ref.slots[ref_slot]
        if not re_.func_name:
            continue
        candidates = target_by_name.get(re_.func_name, [])
        # Prefer the candidate slot closest to the ref slot when names collide
        best = None
        best_dist = 10**9
        for cand in candidates:
            if cand in used_target_slots:
                continue
            d = abs(cand - ref_slot)
            if d < best_dist:
                best_dist = d
                best = cand
        if best is not None:
            sm.ref_to_target[ref_slot] = best
            used_target_slots.add(best)

    # Stage 2: fingerprint match for ref slots not yet matched.
    #
    # Done in TWO passes by distance radius.  Pass A only considers target
    # slots within a small window of the ref slot (catches the >95% of
    # real-world cases where a method moved by 0-3 slots between patches).
    # Pass B widens to a larger window for the rest.  This stops a greedy
    # large-distance fingerprint collision from stealing a near-perfect
    # close-distance match -- e.g., AE PC.Resurrect at slot 0xCC must NOT
    # be consumed by some far-away ref slot whose prologue happens to
    # share the same MSVC frame-setup bytes.
    PASS_A_RADIUS = 3      # tight: catches +/- 0-3 slot shifts
    PASS_B_RADIUS = 32     # wider: catches larger insertions, but only after
                            #         tight matches have locked in nearby slots
    for radius in (PASS_A_RADIUS, PASS_B_RADIUS):
        for ref_slot in sorted(ref.slots):
            if ref_slot in sm.ref_to_target:
                continue
            re_ = ref.slots[ref_slot]
            ref_fp = _normalize_fingerprint(re_.fingerprint)
            if not ref_fp:
                continue
            candidate_order = sorted(
                (s for s in tgt.slots
                 if s not in used_target_slots
                 and abs(s - ref_slot) <= radius),
                key=lambda s: abs(s - ref_slot)
            )
            for cand in candidate_order:
                te = tgt.slots[cand]
                if _fingerprints_match(ref_fp, _normalize_fingerprint(te.fingerprint)):
                    sm.ref_to_target[ref_slot] = cand
                    used_target_slots.add(cand)
                    break

    # Stage 3: identify what's left
    sm.unmatched_ref_slots = [s for s in sorted(ref.slots) if s not in sm.ref_to_target]
    sm.target_only_slots = [
        (s, tgt.slots[s]) for s in sorted(tgt.slots) if s not in used_target_slots
    ]

    if sm.unmatched_ref_slots:
        sm.notes.append('{} ref slots have no target match'.format(len(sm.unmatched_ref_slots)))
    if sm.target_only_slots:
        sm.notes.append('{} target-only slots'.format(len(sm.target_only_slots)))

    return sm


def build_shift_map(ref: BinaryLayout, tgt: BinaryLayout) -> ShiftMap:
    """Compute the full ShiftMap from reference binary -> target binary."""
    out = ShiftMap(reference_label=ref.binary_label, target_label=tgt.binary_label)
    for class_name, ref_vt in ref.classes.items():
        tgt_vt = tgt.get(class_name)
        if tgt_vt is None:
            # Class absent from target binary entirely
            cm = ClassShiftMap(class_name=class_name)
            cm.unmatched_ref_slots = sorted(ref_vt.slots.keys())
            cm.notes.append('class missing from target binary')
            out.classes[class_name] = cm
            continue
        out.classes[class_name] = _match_one_class(ref_vt, tgt_vt)
    return out


def save_json(sm: ShiftMap, path: str) -> None:
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(sm.to_json(), f, indent=2, sort_keys=True)


def load_json(path: str) -> Optional[dict]:
    if not os.path.isfile(path):
        return None
    with open(path, encoding='utf-8') as f:
        return json.load(f)
