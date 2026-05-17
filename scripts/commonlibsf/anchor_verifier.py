"""Anchor verification for parsed vtable structs.

The libclang parse of CommonLib* headers infers vtable slot indices from
the declared virtual method order.  When a patch revision reorders or
inserts virtual methods, that inference silently drifts -- types still
``apply`` cleanly in Ghidra but with the wrong function pointers at the
wrong slot offsets.  Anchor CSVs catch that drift.

Anchor CSV format (header row required):

    class,method,slot,note
    Actor,PlayPickUpSound,0x130,CommonLibSF Actor.h // 130

  ``class``   The C++ class name (without ``_vtbl`` suffix).
  ``method``  Virtual method name expected at the slot.
  ``slot``    Hex slot index (e.g. ``0x130``) -- the value next to the
              ``// XXX`` comment in CommonLibSF's vtable bodies.
  ``note``    Free-form, ignored by the verifier.

Lines starting with ``#`` are comments; blank lines ignored.  Missing or
empty CSVs are a transparent no-op so parsers without anchors keep
working.
"""

from __future__ import annotations

import os
import sys
from typing import List, Optional, Tuple


def _read_anchors(csv_path: str) -> List[Tuple[str, str, int]]:
    rows: List[Tuple[str, str, int]] = []
    if not os.path.isfile(csv_path):
        return rows
    with open(csv_path, encoding='utf-8') as f:
        lines = f.readlines()

    header_seen = False
    for ln, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        parts = [p.strip() for p in line.split(',', 3)]
        # The first non-comment, non-blank row is the header.
        if not header_seen:
            header_seen = True
            lower = [p.lower() for p in parts]
            if lower[:3] == ['class', 'method', 'slot']:
                continue
            # No header — fall through and treat as data.
        if len(parts) < 3:
            print(f'anchor_verifier: {csv_path}:{ln}: '
                  f'expected at least 3 fields, got {len(parts)} -- skipping')
            continue
        cls, method, slot_s = parts[0], parts[1], parts[2]
        try:
            slot = int(slot_s, 0)  # auto-detect base (0x..., decimal)
        except ValueError:
            print(f'anchor_verifier: {csv_path}:{ln}: '
                  f'slot "{slot_s}" not an integer -- skipping')
            continue
        rows.append((cls, method, slot))
    return rows


def _slot_function_name(slot) -> Optional[str]:
    """Extract the function name from a parsed vtable slot entry.

    ghidra_import_gen.build_vtable_structs emits slots in a few shapes
    depending on parser version (dict, tuple, plain string).  Accept any
    of them and return the name or None.
    """
    if isinstance(slot, str):
        return slot
    if isinstance(slot, dict):
        for key in ('name', 'fn', 'func', 'method', 'symbol'):
            v = slot.get(key)
            if isinstance(v, str):
                return v
        return None
    if isinstance(slot, (list, tuple)) and slot:
        first = slot[0]
        if isinstance(first, str):
            return first
    return None


def _find_vtable(vtable_structs: dict, cls: str):
    """Look up the vtable entry for ``cls`` using common naming patterns."""
    for candidate in (cls, f'{cls}_vtbl', f'{cls}Vtbl', f'{cls}::Vtbl'):
        v = vtable_structs.get(candidate)
        if v is not None:
            return candidate, v
    # Fallback: search by class_full_name suffix.
    suffix = f'::{cls}'
    for name, v in vtable_structs.items():
        if not isinstance(v, dict):
            continue
        full = v.get('class_full_name') or ''
        if full == cls or full.endswith(suffix):
            return name, v
    return None, None


def verify_or_exit(version: str, vtable_structs: dict, csv_path: str) -> None:
    """Verify each anchor row against the parsed vtable_structs.

    Exits with code 1 on the first batch of mismatches.  No-op when the
    anchor CSV is missing/empty, or when ``vtable_structs`` is empty
    (e.g. labels-only run without clang).
    """
    anchors = _read_anchors(csv_path)
    if not anchors:
        return
    if not vtable_structs:
        print(f'anchor_verifier[{version}]: skipping {len(anchors)} anchor(s) '
              f'-- no vtable_structs produced (labels-only run?)')
        return

    failures: List[str] = []
    for cls, method, slot in anchors:
        vt_name, vt = _find_vtable(vtable_structs, cls)
        if vt is None:
            failures.append(
                f'  {cls}::{method} @ {slot:#x}: '
                f'no vtable struct named {cls}/{cls}_vtbl found')
            continue
        slots = vt.get('slots') if isinstance(vt, dict) else None
        if not isinstance(slots, (list, tuple)):
            failures.append(
                f'  {cls}[{slot:#x}]: vtable "{vt_name}" has no usable slots list')
            continue
        if slot < 0 or slot >= len(slots):
            failures.append(
                f'  {cls}[{slot:#x}]: out of range '
                f'(vtable "{vt_name}" has {len(slots)} slots)')
            continue
        actual = _slot_function_name(slots[slot])
        if actual != method:
            failures.append(
                f'  {cls}[{slot:#x}]: expected "{method}", got "{actual}" '
                f'(in vtable "{vt_name}")')

    if failures:
        print(f'\nanchor_verifier[{version}]: '
              f'{len(failures)}/{len(anchors)} anchor(s) FAILED:')
        for line in failures:
            print(line)
        print(f'\nFix the parser, update the anchor CSV, or remove stale rows '
              f'in {csv_path} before re-running.')
        sys.exit(1)

    print(f'anchor_verifier[{version}]: {len(anchors)}/{len(anchors)} '
          f'anchor(s) verified.')
