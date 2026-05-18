"""Import legacy on-disk vtable dumps into the unified ``vtable_layout`` CSV format.

The Shared/GhidraAnalysis/ directory already contains hand-extracted vtable
dumps for several game versions in two pre-existing formats:

  - ``f4vr_vtables.txt`` style (pipe-delimited blocks):

        VTABLE|0x142D80F88|PlayerCharacter|300 vfuncs
          VFUNC|0x140F58870|PlayerCharacter::vf000
          VFUNC|0x140049AB0|PlayerCharacter::vf001

  - ``f4ng_vtables.csv`` style (CSV with named columns):

        vtable_address,class_name,slot_index,function_address,function_name

This converter lets the build pipeline reuse those dumps without a full
re-extraction via Ghidra.  Fingerprints are absent (the legacy dumps
didn't capture them), so cross-version matching falls back to name-only
and will be less robust until a re-dump-with-fingerprints is done.
"""
from __future__ import annotations

import csv
import os
import re
from typing import Optional

from vtable_layout import BinaryLayout, SlotEntry, ClassVtable, save_csv


def _is_primary_vtable_name(name: str) -> bool:
    return name and '_' not in name.lstrip('_')


def import_piped_txt(path: str, label: str, only_primary: bool = True) -> BinaryLayout:
    layout = BinaryLayout(binary_label=label, binary_path=path)
    if not os.path.isfile(path):
        return layout
    current: Optional[ClassVtable] = None
    skip_current = False
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip()
            if line.startswith('VTABLE|'):
                parts = line.split('|')
                if len(parts) < 3:
                    current = None; skip_current = True; continue
                addr = int(parts[1], 16)
                cls = parts[2].strip()
                if only_primary and not _is_primary_vtable_name(cls):
                    current = None; skip_current = True; continue
                if cls in layout.classes:
                    current = None; skip_current = True; continue
                current = layout.upsert(cls, addr); skip_current = False
            elif line.lstrip().startswith('VFUNC|'):
                if skip_current or current is None:
                    continue
                parts = line.strip().split('|')
                if len(parts) < 3:
                    continue
                func_addr = int(parts[1], 16)
                tail = parts[2]
                # Ghidra emits `Class::vfNNN` where NNN is the *decimal* slot
                # index (vf000..vf299 for a 300-slot vtable).  Restrict the
                # regex to digits only -- hex chars would falsely match real
                # PDB-named methods like `Actor::vfprintf` or similar.
                slot_match = re.search(r'vf(\d+)$', tail)
                if not slot_match:
                    continue
                slot = int(slot_match.group(1))
                func_name = '' if slot_match else tail
                current.add(SlotEntry(slot=slot, func_addr=func_addr,
                                       func_name=func_name, fingerprint=''))
    return layout


def import_csv(path: str, label: str, only_primary: bool = True) -> BinaryLayout:
    layout = BinaryLayout(binary_label=label, binary_path=path)
    if not os.path.isfile(path):
        return layout
    primary_addr_for_class = {}
    with open(path, newline='', encoding='utf-8', errors='replace') as f:
        for row in csv.DictReader(f):
            cls = (row.get('class_name') or '').strip()
            vaddr_str = (row.get('vtable_address') or '').strip()
            if not cls or not vaddr_str:
                continue
            try:
                vaddr = int(vaddr_str, 16)
            except ValueError:
                continue
            if cls.startswith('MSVCP110.DLL') or 'std::' in cls:
                continue
            if only_primary:
                if cls in primary_addr_for_class:
                    if primary_addr_for_class[cls] != vaddr:
                        continue
                else:
                    primary_addr_for_class[cls] = vaddr
            try:
                slot = int((row.get('slot_index') or '').strip())
                faddr = int((row.get('function_address') or '0').strip(), 16)
            except ValueError:
                continue
            cv = layout.upsert(cls, vaddr)
            cv.add(SlotEntry(slot=slot, func_addr=faddr,
                              func_name=(row.get('function_name') or '').strip(),
                              fingerprint=''))
    return layout


def main():
    import argparse, sys
    p = argparse.ArgumentParser(description='Convert legacy vtable dumps to unified CSV')
    p.add_argument('--source', required=True)
    p.add_argument('--format', choices=['piped', 'csv'], required=True)
    p.add_argument('--label', required=True)
    p.add_argument('--out', required=True)
    args = p.parse_args()
    layout = (import_piped_txt(args.source, args.label) if args.format == 'piped'
              else import_csv(args.source, args.label))
    rows = save_csv(layout, args.out)
    print('Wrote {} rows for {} class(es)'.format(rows, len(layout.classes)))
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
