#!/usr/bin/env python3
"""
Parse libxse/commonlibf4 headers and generate Ghidra import scripts for
Fallout 4 OG / NG / AE / VR.

Pipeline:
  Types:        core/clang_types.py  (clang AST dump + record layouts)
  Relocations:  reloc_parser.py      (IDs.h map + ID::Class::Method references)
  Address lib:  address_library.py   (OG / NG / AE / VR)
  Fallback:     ida_names.py         (extras/IDAImportNames_1.11.191.0.py)
  Script gen:   core/ghidra_import_gen.py

Generates:
  ghidrascripts/CommonLibImport_F4_OG.py   (types/labels only)
  ghidrascripts/CommonLibImport_F4_NG.py   (types + NG-resolved symbols)
  ghidrascripts/CommonLibImport_F4_AE.py   (types + AE-resolved symbols)
  ghidrascripts/CommonLibImport_F4_VR.py   (types/labels only)

Symbol resolution
-----------------
CommonLibF4 IDs are in the NG/AE namespace (1.10.984 / 1.11.191) — those
two DBs share IDs with ~59% overlap, so a single ID resolves against both.
OG (1.10.163) and VR (1.2.72) use entirely disjoint ID namespaces that
CommonLibF4 does not reference, so looking up an AE-namespace ID against
the OG or VR DB only finds coincidental low-ID matches that point at the
wrong functions.  We deliberately do NOT resolve against OG/VR; those
scripts get types + RTTI/VTABLE labels only.  Cross-version function-name
porting for OG/VR is out of scope here (a separate post-pass like masked
byte-signature matching from AE would be the right tool).
"""

import os
import sys
import re

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
CORE_DIR    = os.path.join(os.path.dirname(SCRIPT_DIR), 'core')

sys.path.insert(0, CORE_DIR)
sys.path.insert(0, SCRIPT_DIR)

COMMONLIB_INCLUDE = os.path.join(PROJECT_DIR, 'extern', 'CommonLibF4', 'include')
FALLOUT_H         = os.path.join(COMMONLIB_INCLUDE, 'RE', 'Fallout.h')
RE_INCLUDE        = os.path.join(COMMONLIB_INCLUDE, 'RE')
OUTPUT_DIR        = os.path.join(PROJECT_DIR, 'ghidrascripts')
ADDRLIB_DIR       = os.path.join(PROJECT_DIR, 'addresslibrary', 'f4')


# A descriptor that ends in a single-letter uppercase qualified path is an
# uninstantiated template parameter (``T``, ``K``, ``V``...).  Signatures
# containing such tokens can't point at the exact correct type and are
# dropped instead of being applied with a stale ``RE::T`` placeholder.
_UNRESOLVED_TPARAM_RE = re.compile(r'(?:^|[:>])([A-Z])(?=$|\W)')


def _has_unresolved_tparam(desc):
    if not desc:
        return False
    if 'struct:' not in desc and 'enum:' not in desc:
        return False
    return bool(_UNRESOLVED_TPARAM_RE.search(desc))


def _enrich_symbols(symbols_list, structs):
    structs_by_suffix = {}
    for key, val in structs.items():
        parts = key.split('::')
        for i in range(len(parts)):
            suffix = '::'.join(parts[i:])
            if suffix not in structs_by_suffix:
                structs_by_suffix[suffix] = val
    enriched = 0
    skipped = 0
    for sym in symbols_list:
        if sym['t'] != 'func' or sym.get('sd'):
            continue
        name = sym['n']
        if '::' not in name:
            continue
        idx = name.rfind('::')
        class_name  = name[:idx]
        method_name = name[idx + 2:]
        st = structs.get(class_name) or structs_by_suffix.get(class_name)
        if not st:
            continue
        info = st.get('methods', {}).get(method_name)
        if info:
            ret, params, is_static = info
            # Reject signatures containing uninstantiated template parameters
            # (e.g. ``T*`` from a class template's method) — they would resolve
            # to ``void*`` in Ghidra and mask the real types in the binary.
            if _has_unresolved_tparam(ret) or any(_has_unresolved_tparam(p[1]) for p in params):
                skipped += 1
                continue
            sym['sd'] = [ret, params, 1 if is_static else 0]
            enriched += 1
    if enriched:
        print(f'Enriched {enriched} symbols with AST method signatures')
    if skipped:
        print(f'Skipped {skipped} symbols with uninstantiated template params in signature')


# Per-version output config.  OG/VR have no fallback symbol pool — their
# IDs are in disjoint namespaces, so an AE-namespace fallback would
# poison the import with mislabeled functions.
F4_TARGETS = (
    ('f4_og', 'CommonLibImport_F4_OG.py', '[]'),
    ('f4_ng', 'CommonLibImport_F4_NG.py', '[]'),
    ('f4_ae', 'CommonLibImport_F4_AE.py', None),   # filled in with IDA fallback
    ('f4_vr', 'CommonLibImport_F4_VR.py', '[]'),
)


def main():
    import json as _json

    from address_library import F4AddressLibrary
    from ghidra_import_gen import (
        build_vtable_structs as _build_vtable_structs,
        inject_vtable_fields as _inject_vtable_fields,
        flatten_structs       as _flatten_structs,
        apply_secondary_vtable_typing as _apply_secondary_vtable_typing,
        generate_script,
    )

    # --- Address library (OG / NG / AE / VR) ---
    addr_lib = F4AddressLibrary()
    addr_lib.load_all(ADDRLIB_DIR)
    print(f'Address libraries — OG: {len(addr_lib.og_db):,}, '
          f'NG: {len(addr_lib.ng_db):,}, AE: {len(addr_lib.ae_db):,}, '
          f'VR: {len(addr_lib.vr_db):,}')

    # --- Relocation scan ---
    print('\n=== Collecting symbols via relocation parser ===')
    import reloc_parser as _rp

    func_syms, label_syms, static_methods = _rp.collect_relocations(
        RE_INCLUDE, addr_lib, verbose=True)

    # Mark statics
    for fs in func_syms:
        if fs.get('class_') and fs.get('name'):
            if (fs['class_'], fs['name']) in static_methods:
                fs['is_static'] = True

    # CommonLibF4 IDs are in the NG/AE namespace.  Resolve each ID against
    # both NG and AE; the 'a' key stays as AE for backward compatibility.
    def _resolve(sym, id_val):
        if not id_val:
            return
        ng = addr_lib.ng_db.get(id_val)
        ae = addr_lib.ae_db.get(id_val)
        if ng: sym['ng'] = ng
        if ae: sym['a']  = ae

    symbols = []
    for fs in func_syms:
        full_name = '{}::{}'.format(fs['class_'], fs['name']) if fs['class_'] else fs['name']
        sym = {'n': full_name, 't': 'func', 'sig': '', 'src': 'CommonLibF4'}
        if fs.get('id'):
            sym['id'] = fs['id']
        _resolve(sym, fs.get('id'))
        symbols.append(sym)

    for lbl in label_syms:
        sym = {'n': lbl['name'], 't': 'label', 'sig': '', 'src': 'CommonLibF4'}
        if lbl.get('id'):
            sym['id'] = lbl['id']
        _resolve(sym, lbl.get('id'))
        symbols.append(sym)

    # Normalise __ -> ::
    for s in symbols:
        if '__' in s['n']:
            s['n'] = re.sub(r':{3,}', '::', s['n'].replace('__', '::'))

    n_ng = sum(1 for s in symbols if 'ng' in s)
    n_ae = sum(1 for s in symbols if 'a'  in s)
    print(f'\nTotal symbols: {len(symbols)} (NG: {n_ng}, AE: {n_ae}) '
          f'— OG/VR get types + labels only (disjoint ID namespaces)')

    # --- Type parsing ---
    print('\n=== Parsing types (clang AST) ===')
    from clang_types import collect_types, _setup_include_paths

    if not os.path.isfile(FALLOUT_H):
        print('ERROR: Could not find Fallout.h at', FALLOUT_H)
        sys.exit(1)

    stub_dir   = os.path.join(os.path.dirname(SCRIPT_DIR), 'core', '_clang_stubs')
    parse_args = _setup_include_paths(COMMONLIB_INCLUDE, stub_dir)
    # commonlib-shared provides REL/ and REX/ headers
    shared_include = os.path.join(PROJECT_DIR, 'extern', 'CommonLibF4', 'lib', 'commonlib-shared', 'include')
    if os.path.isdir(shared_include):
        parse_args = ['-I' + shared_include] + parse_args

    # Capture types from REL/, REX/, F4SE/ as well as RE/ — they're sibling
    # namespaces under CommonLibF4 whose AST methods would otherwise be skipped.
    extra_scopes = [
        COMMONLIB_INCLUDE,                                   # F4SE/ + RE/
        os.path.join(PROJECT_DIR, 'extern', 'CommonLibF4',
                     'lib', 'commonlib-shared', 'include'),  # REL/ + REX/
    ]
    enums, structs, template_source = collect_types(
        FALLOUT_H, RE_INCLUDE, parse_args,
        verbose=True, category_prefix='/CommonLibF4',
        extra_scope_paths=extra_scopes)
    print(f'Found {len(enums)} enums, {len(structs)} structs/classes')

    _enrich_symbols(symbols, structs)

    vtable_structs = _build_vtable_structs(structs)
    _inject_vtable_fields(structs, vtable_structs)
    _flatten_structs(structs)
    _apply_secondary_vtable_typing(structs)

    # --- IDAImportNames_1.11.191.0.py fallback symbols (AE only) ---
    print('\n=== Loading IDAImportNames_1.11.191.0.py fallback symbols ===')
    from ida_names import load_ida_import_names as _load_ida
    f4_ida_path = os.path.join(PROJECT_DIR, 'extras', 'IDAImportNames_1.11.191.0.py')
    ida_names = _load_ida(f4_ida_path)
    print(f'IDA names: {len(ida_names):,} entries')

    primary_rvas = {s['a'] for s in symbols if s.get('a')}
    ida_fallback = [
        {'n': name, 't': 'func', 'sig': '', 'a': rva, 'src': 'IDAImportNames'}
        for rva, name in ida_names.items()
    ]
    not_in_primary = sum(1 for s in ida_fallback if s['a'] not in primary_rvas)
    print(f'IDA fallback symbols: {len(ida_fallback):,} loaded '
          f'({not_in_primary:,} not in primary)')

    fallback_json_ae = _json.dumps(ida_fallback, separators=(',', ':'))
    symbols_json     = _json.dumps(symbols, separators=(',', ':'))

    # --- Generate per-version scripts ---
    print('\nGenerating Ghidra scripts...')
    for ver, fname, fb_json in F4_TARGETS:
        if fb_json is None:
            fb_json = fallback_json_ae
        output_path = os.path.join(OUTPUT_DIR, fname)
        n_enums, n_structs = generate_script(
            enums, structs, vtable_structs, output_path,
            version=ver,
            symbols_json=symbols_json,
            fallback_symbols_json=fb_json,
            template_source=template_source,
            project_name='CommonLibF4',
        )
        print(f'  {fname}: {n_enums} enums, {n_structs} structs')


if __name__ == '__main__':
    main()
