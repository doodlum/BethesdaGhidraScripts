#!/usr/bin/env python3
"""
Parse CommonLibSSE headers and generate Ghidra import scripts that create
struct/class/enum type definitions with function symbols and relocations.

Run with: python parse_commonlib_types.py

Pipeline:
  Types:        clang_types.py  (clang.exe AST dump + record layouts)
  Templates:    template_types.py  (template instantiation name discovery)
  Relocations:  reloc_parser.py  (regex-based, single-pass SE+AE from raw source)
  PDB symbols:  pdb_symbols.py  (SkyrimSE.pdb public function names via pdbparse)
  AE names:     skyrimae.rename  (AE address ID → name mapping, fallback)
  Script gen:   ghidra_import_gen.py  (Ghidra Jython script emitter)

Generates two scripts: CommonLibImport_SE.py and CommonLibImport_AE.py.
"""

import os
import sys
import re

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))

from address_library import AddressLibrary
from pdb_symbols import load_pdb_names as load_se_pdb_names
from ghidra_import_gen import (
    build_vtable_structs as _build_vtable_structs,
    inject_vtable_fields as _inject_vtable_fields,
    flatten_structs as _flatten_structs,
    apply_secondary_vtable_typing as _apply_secondary_vtable_typing,
    generate_script,
)
from anchor_verifier import verify_or_exit as _verify_anchors_or_exit

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
COMMONLIB_INCLUDE = os.path.join(PROJECT_DIR, 'extern', 'CommonLibSSE', 'include')
SKYRIM_H = os.path.join(COMMONLIB_INCLUDE, 'RE', 'Skyrim.h')
RE_INCLUDE = os.path.join(COMMONLIB_INCLUDE, 'RE')
OUTPUT_DIR = os.path.join(PROJECT_DIR, 'ghidrascripts')

# ---------------------------------------------------------------------------
# AE rename database
# ---------------------------------------------------------------------------

def load_ae_rename_db(file_path, ae_db):
    """Load skyrimae.rename: lines of '<ae_id> <name>', skip version line."""
    result = {}  # ae_offset -> name
    if not os.path.exists(file_path):
        return result
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    for line in lines[1:]:  # skip version line
        line = line.strip()
        if not line:
            continue
        parts = line.split(' ', 1)
        if len(parts) != 2:
            continue
        name = parts[1].rstrip('*').rstrip('_')
        try:
            ae_id = int(parts[0])
        except ValueError:
            continue
        off = ae_db.get(ae_id)
        if off:
            result[off] = name
    return result


VERSIONS = {
    'se': {
        'defines':     [],
        'output':      os.path.join(OUTPUT_DIR, 'CommonLibImport_SE.py'),
    },
    'ae': {
        'defines':     ['-DSKYRIM_AE', '-DSKYRIM_SUPPORT_AE'],
        'output':      os.path.join(OUTPUT_DIR, 'CommonLibImport_AE.py'),
    },
    'svr': {
        # Skyrim VR (1.4.15) — same headers as SE; symbols come from VR
        # offsets looked up via the SE-namespace ID (SE and VR share the
        # same ID space).  The powerof3 CommonLibSSE fork has no
        # VR-specific preprocessor define, so we parse with the SE define
        # set and just attach VR offsets at script-generation time.
        'defines':     [],
        'output':      os.path.join(OUTPUT_DIR, 'CommonLibImport_VR.py'),
    },
}



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


def _enrich_symbols_with_sigs(symbols_json, structs):
    """Cross-reference symbols with AST method signatures.

    For each function symbol like 'Actor::AddSpell', look up the method
    signature from structs['Actor']['methods']['AddSpell'] and store
    structured pipeline type data for direct FunctionDefinitionDataType
    construction (bypasses CParserUtils).
    """
    import json as _json
    symbols = _json.loads(symbols_json)
    structs_by_suffix = {}
    for key, val in structs.items():
        parts = key.split('::')
        for i in range(len(parts)):
            suffix = '::'.join(parts[i:])
            if suffix not in structs_by_suffix:
                structs_by_suffix[suffix] = val
    enriched = 0
    skipped = 0
    for sym in symbols:
        if sym['t'] != 'func' or sym.get('sd'):
            continue
        name = sym['n']
        if '::' not in name:
            continue
        idx = name.rfind('::')
        class_name = name[:idx]
        method_name = name[idx + 2:]
        st = structs.get(class_name) or structs_by_suffix.get(class_name)
        if not st:
            continue
        methods = st.get('methods', {})
        info = methods.get(method_name)
        if not info and method_name == 'operator':
            info = methods.get('operator()')
        if not info:
            continue
        ret, params, is_static = info
        if _has_unresolved_tparam(ret) or any(_has_unresolved_tparam(p[1]) for p in params):
            skipped += 1
            continue
        sym['sd'] = [ret, params, 1 if is_static else 0]
        enriched += 1
    if enriched:
        print('Enriched {} symbols with AST method signatures'.format(enriched))
    if skipped:
        print('Skipped {} symbols with uninstantiated template params in signature'.format(skipped))
    return _json.dumps(symbols, separators=(',', ':'))


def run_version(version, symbols_json, fallback_symbols_json='[]'):
    from clang_types import collect_types, _setup_include_paths

    cfg = VERSIONS[version]
    output_path = cfg['output']
    stub_dir = os.path.join(os.path.dirname(SCRIPT_DIR), 'core', '_clang_stubs')
    parse_args = _setup_include_paths(COMMONLIB_INCLUDE, stub_dir) + cfg['defines']

    print('\n=== {} ==='.format(version.upper()))

    if not os.path.isfile(SKYRIM_H):
        print('ERROR: Could not find Skyrim.h at', SKYRIM_H)
        sys.exit(1)

    # Capture types from sibling namespaces (REL, REX, SKSE) under the
    # CommonLibSSE include root — without this the AST extraction would skip
    # methods declared outside the RE/ subdirectory.
    enums, structs, template_source = collect_types(
        SKYRIM_H, RE_INCLUDE, parse_args,
        verbose=True,
        extra_scope_paths=[COMMONLIB_INCLUDE],
    )
    print('Found {} enums, {} structs/classes'.format(len(enums), len(structs)))

    symbols_json = _enrich_symbols_with_sigs(symbols_json, structs)

    vtable_structs = _build_vtable_structs(structs)
    _inject_vtable_fields(structs, vtable_structs)
    _flatten_structs(structs)
    _apply_secondary_vtable_typing(structs)

    # Verify hand-checked vtable slot anchors for this runtime before emitting
    # the script.  Catches silent layout drift (e.g. VR insertion points) that
    # the shared-header AST parse cannot otherwise see.  Fatal on mismatch.
    anchors_csv = os.path.join(SCRIPT_DIR, 'anchors', '{}.csv'.format(version))
    _verify_anchors_or_exit(version, vtable_structs, anchors_csv)

    print('Generating Ghidra script...')
    n_enums, n_structs = generate_script(enums, structs, vtable_structs, output_path, version, symbols_json, fallback_symbols_json, template_source)
    print('Output: {} ({} enums, {} structs)'.format(output_path, n_enums, n_structs))


def main():
    import json as _json

    # Load address databases (binary data, not source scanning)
    addr_lib = AddressLibrary()
    addr_lib.load_all(os.path.join(PROJECT_DIR, 'addresslibrary'))
    print('SE entries: {}, AE entries: {}'.format(len(addr_lib.se_db), len(addr_lib.ae_db)))

    print('\n=== Collecting symbols via regex relocation parser ===')
    import reloc_parser as _rp

    func_syms, label_syms, offset_id_map, static_methods, se_offset_map, ae_offset_map = _rp.collect_relocations(
        RE_INCLUDE, addr_lib, verbose=True)

    src_dir = os.path.join(PROJECT_DIR, 'extern', 'CommonLibSSE', 'src')
    if os.path.isdir(src_dir):
        src_func_syms = _rp.collect_src_relocations(
            src_dir, addr_lib, offset_id_map,
            se_offset_map=se_offset_map, ae_offset_map=ae_offset_map,
            verbose=True)
    else:
        src_func_syms = []
        print('  src/ dir not found, skipping')

    label_by_name = {}
    for lbl in label_syms:
        label_by_name.setdefault(lbl['name'], {
            'name': lbl['name'], 'se_off': None, 'ae_off': None, 'vr_off': None})
        entry = label_by_name[lbl['name']]
        if lbl.get('se_off'): entry['se_off'] = lbl['se_off']
        if lbl.get('ae_off'): entry['ae_off'] = lbl['ae_off']
        if lbl.get('vr_off'): entry['vr_off'] = lbl['vr_off']

    merged_funcs = list(func_syms)
    seen_se = set(fs['se_off'] for fs in merged_funcs if fs.get('se_off'))
    seen_ae = set(fs['ae_off'] for fs in merged_funcs if fs.get('ae_off'))

    for fs in src_func_syms:
        if not fs.get('is_static') and fs.get('class_') and fs.get('name'):
            if (fs['class_'], fs['name']) in static_methods:
                fs['is_static'] = True

    for fs in src_func_syms:
        se_off = fs.get('se_off')
        ae_off = fs.get('ae_off')
        if se_off and se_off in seen_se:
            continue
        if ae_off and ae_off in seen_ae:
            continue
        if se_off: seen_se.add(se_off)
        if ae_off: seen_ae.add(ae_off)
        merged_funcs.append(fs)

    # Build SYMBOLS array
    symbols = []
    sym_seen_se = set()
    sym_seen_ae = set()

    # Function symbols
    for fs in merged_funcs:
        full_name = '{}::{}'.format(fs['class_'], fs['name']) if fs['class_'] else fs['name']
        sig = ''
        if fs.get('ret'):
            sig = '{}({})'.format(fs['ret'], fs.get('params', ''))
            if fs.get('is_static'):
                sig = 'static ' + sig
        sym = {'n': full_name, 't': 'func', 'sig': sig, 'src': 'CommonLibSSE'}
        if fs['se_off']: sym['s'] = fs['se_off']; sym_seen_se.add(fs['se_off'])
        if fs['ae_off']: sym['a'] = fs['ae_off']; sym_seen_ae.add(fs['ae_off'])
        if fs.get('vr_off'): sym['v'] = fs['vr_off']
        symbols.append(sym)

    # RTTI/VTABLE labels
    for lbl in label_by_name.values():
        sym = {'n': lbl['name'], 't': 'label', 'sig': '', 'src': 'CommonLibSSE'}
        if lbl['se_off']: sym['s'] = lbl['se_off']; sym_seen_se.add(lbl['se_off'])
        if lbl['ae_off']: sym['a'] = lbl['ae_off']; sym_seen_ae.add(lbl['ae_off'])
        if lbl.get('vr_off'): sym['v'] = lbl['vr_off']
        symbols.append(sym)

    name_to_sym = {s['n']: s for s in symbols}

    # AE rename database fallback
    rename_db = os.path.join(PROJECT_DIR, 'extern', 'AddressLibraryDatabase', 'skyrimae.rename')
    ae_rename = load_ae_rename_db(rename_db, addr_lib.ae_db)
    rename_added = rename_merged = 0
    for ae_off, name in ae_rename.items():
        if ae_off in sym_seen_ae:
            continue
        if name in name_to_sym:
            existing = name_to_sym[name]
            if not existing.get('a'):
                existing['a'] = ae_off
                sym_seen_ae.add(ae_off)
                rename_merged += 1
            continue
        sym_seen_ae.add(ae_off)
        sym = {'n': name, 't': 'func', 'sig': '', 'a': ae_off, 'src': 'skyrimae.rename'}
        symbols.append(sym)
        name_to_sym[name] = sym
        rename_added += 1
    print('Added {} new symbols from AE rename, merged AE offset into {} existing'.format(
        rename_added, rename_merged))

    # SE PDB public symbols fallback
    se_pdb_path = os.path.join(PROJECT_DIR, 'extras', 'SkyrimSE.pdb')
    se_pdb_names = load_se_pdb_names(se_pdb_path)
    pdb_added = pdb_merged = 0
    for se_off, name in se_pdb_names.items():
        if se_off in sym_seen_se:
            continue
        if name in name_to_sym:
            existing = name_to_sym[name]
            if not existing.get('s'):
                existing['s'] = se_off
                sym_seen_se.add(se_off)
                pdb_merged += 1
            continue
        sym_seen_se.add(se_off)
        sym = {'n': name, 't': 'func', 'sig': '', 's': se_off, 'src': 'SkyrimSE.pdb'}
        symbols.append(sym)
        name_to_sym[name] = sym
        pdb_added += 1
    print('Added {} new symbols from SE PDB, merged SE offset into {} existing'.format(
        pdb_added, pdb_merged))

    # Normalize __ → :: in all names
    for s in symbols:
        if '__' in s['n']:
            s['n'] = re.sub(r':{3,}', '::', s['n'].replace('__', '::'))

    funcs = [s for s in symbols if s['t'] == 'func']
    with_sig = len([s for s in funcs if s.get('sig')])
    labels_count = len([s for s in symbols if s['t'] == 'label'])
    print('\nGenerated {} symbols:'.format(len(symbols)))
    print('  Functions: {} ({} with signatures)'.format(len(funcs), with_sig))
    print('  Labels: {}'.format(labels_count))

    _FALLBACK_SRCS = {'skyrimae.rename', 'SkyrimSE.pdb'}
    primary_symbols  = [s for s in symbols if s.get('src') not in _FALLBACK_SRCS]
    fallback_symbols = [s for s in symbols if s.get('src') in _FALLBACK_SRCS]
    print('  Primary: {}, Fallback (AE rename / SE PDB new): {}'.format(
        len(primary_symbols), len(fallback_symbols)))

    symbols_json = _json.dumps(primary_symbols, separators=(',', ':'))

    se_fallback = [s for s in fallback_symbols if s.get('src') == 'SkyrimSE.pdb']
    ae_fallback = [s for s in fallback_symbols if s.get('src') == 'skyrimae.rename']
    print('  SE fallback: {} (PDB), AE fallback: {} (rename DB)'.format(
        len(se_fallback), len(ae_fallback)))

    se_fallback_json = _json.dumps(se_fallback, separators=(',', ':'))
    ae_fallback_json = _json.dumps(ae_fallback, separators=(',', ':'))

    n_v = sum(1 for s in primary_symbols if s.get('v'))
    print('  VR coverage: {} symbols (SE-namespace IDs resolved against vr_db)'.format(n_v))

    fb_for = {
        'se':  se_fallback_json,
        'ae':  ae_fallback_json,
        'svr': '[]',
    }
    for version in ('se', 'ae', 'svr'):
        run_version(version, symbols_json, fb_for[version])


if __name__ == '__main__':
    main()
