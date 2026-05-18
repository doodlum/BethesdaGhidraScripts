"""Build-time vtable struct patcher.

Applies a per-version shift map (from ``vtable_matcher.build_shift_map``)
to the ``vtable_structs`` dict produced by ``ghidra_import_gen.build_vtable_structs``.

For each class with a shift map entry:
  * Each slot in the header-shaped vtable struct gets its byte offset
    remapped to the version's actual binary slot.  Field name is unchanged.
  * Ref slots with no target match are dropped from the version's struct.
  * Target-only slots (new in this version) get placeholder fields
    ``__<version>_only_0xXX`` so the struct overlay is complete.

The caller is expected to run the anchor verifier *after* patching to
sanity-check the result against a hand-curated truth table.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple


def _candidate_struct_keys(class_name: str):
    yield class_name
    if '::' not in class_name:
        yield 'RE::' + class_name
    elif class_name.startswith('RE::'):
        yield class_name[len('RE::'):]


def _resolve_struct(vtable_structs: dict, class_name: str) -> Optional[Tuple[str, dict]]:
    for key in _candidate_struct_keys(class_name):
        st = vtable_structs.get(key)
        if st is not None:
            return key, st
    return None


def patch_vtable_structs(vtable_structs: dict, shift_map_json: dict,
                          version_label: str, verbose: bool = True) -> dict:
    """Apply a shift map JSON (as returned by ShiftMap.to_json) to vtable_structs.

    Mutates and returns ``vtable_structs``.  Each class entry's ``slots``
    list (tuples of ``(byte_off, name, ret, params)``) is replaced.

    Classes without a shift-map entry are left untouched -- this is by
    design, so a partial shift map (covering just hot classes) still
    works; uncovered classes fall back to the header-shaped layout and
    the anchor verifier will catch any drift for those.
    """
    if not shift_map_json or 'classes' not in shift_map_json:
        return vtable_structs

    sm_classes = shift_map_json['classes']
    n_patched = 0
    n_unmatched_classes = 0

    for cls_name, sm_entry in sm_classes.items():
        resolved = _resolve_struct(vtable_structs, cls_name)
        if not resolved:
            n_unmatched_classes += 1
            continue
        struct_key, struct = resolved

        ref_to_target = {
            int(k, 16): int(v, 16)
            for k, v in sm_entry.get('ref_to_target', {}).items()
        }
        target_only = sm_entry.get('target_only_slots', []) or []

        old_slots = struct.get('slots', [])
        new_slots = []
        for slot in old_slots:
            # slot tuple: (byte_off, name, ret, params)
            byte_off, name, ret, params = slot[0], slot[1], slot[2], slot[3]
            ref_slot = byte_off // 8
            if ref_slot in ref_to_target:
                new_byte_off = ref_to_target[ref_slot] * 8
                new_slots.append((new_byte_off, name, ret, params))
            # else: drop -- this slot doesn't exist in target

        # Add target-only placeholder fields
        for entry in target_only:
            tgt_slot = int(entry['slot'], 16)
            label = entry.get('func_name') or '__{}_only_{}'.format(
                version_label, entry['slot'])
            # Sanitize: '__only_' fields shouldn't collide with real names
            new_slots.append((tgt_slot * 8, label, None, None))

        # Re-sort by byte offset and recompute size
        new_slots.sort(key=lambda t: t[0])
        max_off = new_slots[-1][0] if new_slots else 0
        struct['slots'] = new_slots
        struct['size'] = max_off + 8 if new_slots else struct.get('size', 0)
        n_patched += 1

    if verbose:
        print('  patched {} class vtable struct(s) via shift map [{}]'.format(
            n_patched, version_label))
        if n_unmatched_classes:
            print('  {} shift-map classes had no matching vtable_structs entry'.format(
                n_unmatched_classes))

    return vtable_structs
