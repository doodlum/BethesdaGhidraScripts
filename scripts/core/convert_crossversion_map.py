"""Split a multi-version cross-reference vtable map into per-version layout CSVs.

Source format (Shared/GhidraAnalysis/CrossVersionMaps/fallout4_vtable_slots.csv)::

    class_mangled,col_offset,slot,og,ng,ae,vr
    .?AVPlayerCharacter@@,0,207,0xe9d530,0xcd2f30,0xd58a30,0xf06500

Each `og`/`ng`/`ae`/`vr` column is the function address (without `0x14`
image base) at slot `N` of `class_mangled`'s primary vtable in that
version's binary.  *The slot index is shared across versions in this CSV
-- meaning the source assumed the same vtable layout in every version,
which is wrong when patches insert new vfuncs.*  We DO NOT use the
cross-version pairing here.  We use only the per-(version, class, slot)
function address to construct each version's actual layout.

The matcher (vtable_matcher.build_shift_map) then derives correct
slot-to-slot correspondences across versions by joining on function
name + fingerprint, not by slot identity.

Output: one ``BinaryLayout`` CSV per version, written to the requested
output directory using filenames ``<version>_vtables.csv``.
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import sys

from vtable_layout import BinaryLayout, SlotEntry, save_csv


# MSVC RTTI mangled class names like ".?AVPlayerCharacter@@" or
# ".?AU?$BSTArray@VBSEntitlement@BSPlatform@@VBSTArrayHeapAllocator@@@@".
# Strip the ".?AV" / ".?AU" prefix and trailing "@@", reverse @-separated
# parts, leaving us with a CommonLib-style namespace path.
def demangle_rtti(s: str) -> str:
    if not s.startswith('.?A') or not s.endswith('@@'):
        return s
    inner = s[4:-2]  # strip .?AV / .?AU and trailing @@
    # Template instantiations contain nested @s; we can't fully reverse-engineer
    # the C++ source name from RTTI, but the leaf-most segment is the unqualified
    # class name we care about.
    if inner.startswith('?$'):
        # Template -- everything up to the next '@' is the template base name
        m = re.match(r'\?\$([A-Za-z_][A-Za-z_0-9]*)', inner)
        return m.group(1) if m else inner
    parts = [p for p in inner.split('@') if p]
    if not parts:
        return inner
    # MSVC writes namespaces right-to-left; the leaf class is first.
    return parts[0]


VERSION_COLS = {
    'f4_og': 'og',
    'f4_ng': 'ng',
    'f4_ae': 'ae',
    'f4_vr': 'vr',
}

# Standard PE image base for F4 binaries (`140000000` per memory).
IMAGE_BASE = 0x140000000


def convert(source_csv: str, out_dir: str, image_base: int = IMAGE_BASE,
             only_primary_vtable: bool = True, verbose: bool = True) -> dict:
    """Returns {version_label: BinaryLayout}.  Also writes one CSV per version."""
    layouts = {label: BinaryLayout(binary_label=label, binary_path=source_csv)
               for label in VERSION_COLS}

    n_rows = 0
    n_skipped_non_primary = 0

    with open(source_csv, newline='', encoding='utf-8', errors='replace') as f:
        for row in csv.DictReader(f):
            mangled = (row.get('class_mangled') or '').strip()
            if not mangled:
                continue
            try:
                col_offset = int(row.get('col_offset') or '0')
                slot = int(row.get('slot') or '0')
            except ValueError:
                continue
            if only_primary_vtable and col_offset != 0:
                n_skipped_non_primary += 1
                continue

            cls = demangle_rtti(mangled)
            if not cls:
                continue
            n_rows += 1

            for label, col_key in VERSION_COLS.items():
                addr_raw = (row.get(col_key) or '').strip()
                if not addr_raw or addr_raw == '0' or addr_raw == '-':
                    continue
                try:
                    rva = int(addr_raw, 16)
                except ValueError:
                    continue
                func_addr = rva + image_base if rva < image_base else rva
                cv = layouts[label].upsert(cls, 0)  # vtable_addr left 0 (not in source)
                cv.add(SlotEntry(
                    slot=slot,
                    func_addr=func_addr,
                    func_name='',  # populated by enrich_layout.py against per-version PDB
                    fingerprint='',
                ))

    if verbose:
        print(f'Parsed {n_rows} primary-vtable slot rows '
              f'({n_skipped_non_primary} non-primary skipped)')

    os.makedirs(out_dir, exist_ok=True)
    for label, layout in layouts.items():
        path = os.path.join(out_dir, f'{label}_vtables.csv')
        n = save_csv(layout, path)
        if verbose:
            print(f'  {label}: {len(layout.classes)} classes, {n} slots -> {path}')

    return layouts


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', required=True, help='multi-version vtable_slots CSV')
    p.add_argument('--out-dir', required=True, help='output directory for per-version CSVs')
    p.add_argument('--include-secondary', action='store_true',
                   help='include col_offset != 0 secondary inheritance vtables')
    args = p.parse_args()
    convert(args.source, args.out_dir, only_primary_vtable=not args.include_secondary)
    return 0


if __name__ == '__main__':
    sys.exit(main())
