"""CLI: build a per-version shift map from two ``vtable_layout`` CSVs.

Use after running ``vtable_dumper.py`` on both a reference binary
(canonical version that CommonLib's headers describe) and a target
binary (the version whose script we want to ship).

Example::

    python -m build_shift_map \
        --ref scripts/commonlibsse/refs/se_vtables.csv \
        --ref-label se \
        --target scripts/commonlibsse/refs/svr_vtables.csv \
        --target-label svr \
        --out scripts/commonlibsse/refs/shift_svr.json
"""
from __future__ import annotations

import argparse
import sys

from vtable_layout import load_csv
from vtable_matcher import build_shift_map, save_json


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ref', required=True, help='reference layout CSV')
    p.add_argument('--ref-label', required=True)
    p.add_argument('--target', required=True, help='target layout CSV')
    p.add_argument('--target-label', required=True)
    p.add_argument('--out', required=True, help='output shift map JSON')
    args = p.parse_args()

    ref = load_csv(args.ref, args.ref_label)
    tgt = load_csv(args.target, args.target_label)
    print('Reference: {} classes ({} slots)'.format(
        len(ref.classes), sum(len(c.slots) for c in ref.classes.values())))
    print('Target:    {} classes ({} slots)'.format(
        len(tgt.classes), sum(len(c.slots) for c in tgt.classes.values())))

    sm = build_shift_map(ref, tgt)

    # Brief diagnostic
    n_matched = sum(len(c.ref_to_target) for c in sm.classes.values())
    n_unmatched_ref = sum(len(c.unmatched_ref_slots) for c in sm.classes.values())
    n_target_only = sum(len(c.target_only_slots) for c in sm.classes.values())
    print('Matched ref->target slots: {}'.format(n_matched))
    print('Unmatched ref slots:       {}'.format(n_unmatched_ref))
    print('Target-only slots:         {}'.format(n_target_only))

    save_json(sm, args.out)
    print('Wrote shift map: {}'.format(args.out))
    return 0


if __name__ == '__main__':
    sys.exit(main())
