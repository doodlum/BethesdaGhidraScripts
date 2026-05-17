#!/usr/bin/env python3
"""
Parse CommonLibSF headers and generate a Ghidra import script for Starfield.

Single-version pipeline (no SE/AE-style branching).  Symbol sources, in
priority order:

  1. ``RE/IDs.h``         function IDs grouped by ``namespace RE::ID::<Class>``
  2. ``RE/IDs_RTTI.h``    flat ``RTTI_*`` labels
  3. ``RE/IDs_NiRTTI.h``  flat ``NiRTTI_*`` labels
  4. ``RE/IDs_VTABLE.h``  ``std::array<REL::ID, N> VTABLE_*`` slots
  5. clang AST + record-layouts on ``RE/Starfield.h`` for type definitions
     (best-effort -- if the libclang parse fails, fall through to a
     label/symbol-only script)

Output: ``ghidrascripts/CommonLibImport_SF.py``.
"""

import json as _json
import os
import re
import sys

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
COMMONLIB_INCLUDE = os.path.join(PROJECT_DIR, 'extern', 'CommonLibSF', 'include')
STARFIELD_H = os.path.join(COMMONLIB_INCLUDE, 'RE', 'Starfield.h')
RE_INCLUDE  = os.path.join(COMMONLIB_INCLUDE, 'RE')
OUTPUT_DIR  = os.path.join(PROJECT_DIR, 'ghidrascripts')

sys.path.insert(0, os.path.join(SCRIPT_DIR))
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), 'core'))

from address_library import AddressLibrary
from ids_parser import collect_all as collect_id_symbols


def _make_symbols(funcs, labels):
    """Convert ids_parser output into the SYMBOLS array used by the import script.

    ``sf_off`` carries the offset; the script-side ``version_key`` map
    looks symbols up by the ``'sf'`` key (see scripts/core/ghidra_import_gen.py).
    """
    symbols = []
    seen = set()

    for f in funcs:
        full_name = '{}::{}'.format(f['class_'], f['name']) if f.get('class_') else f['name']
        key = (full_name, 'func', f['sf_off'])
        if key in seen:
            continue
        seen.add(key)
        symbols.append({
            'n':   full_name,
            't':   'func',
            'sig': '',
            'sf':  f['sf_off'],
            'src': 'CommonLibSF',
        })

    for l in labels:
        key = (l['name'], 'label', l['sf_off'])
        if key in seen:
            continue
        seen.add(key)
        symbols.append({
            'n':   l['name'],
            't':   'label',
            'sig': '',
            'sf':  l['sf_off'],
            'src': 'CommonLibSF',
        })

    return symbols


def _try_clang_types(verbose=True):
    """Best-effort clang AST parse of CommonLibSF headers.

    Wrapped in a broad try/except: CommonLibSF uses C++23 features and may
    need additional system include stubs.  When the parse fails we return
    empty type containers so the rest of the pipeline still produces a
    usable labels-only script.
    """
    try:
        from clang_types import collect_types, _setup_include_paths
        from ghidra_import_gen import (
            build_vtable_structs,
            inject_vtable_fields,
            flatten_structs,
            apply_secondary_vtable_typing,
        )

        stub_dir   = os.path.join(os.path.dirname(SCRIPT_DIR), 'core', '_clang_stubs')
        parse_args = _setup_include_paths(COMMONLIB_INCLUDE, stub_dir)
        # CommonLibSF uses C++23 features.  -std=c++23 is widely supported by
        # recent clang; older clang falls back to c++latest.
        parse_args = ['-std=c++23'] + parse_args

        if verbose:
            print('Parsing CommonLibSF headers via clang AST...')
        enums, structs, template_source = collect_types(
            STARFIELD_H, RE_INCLUDE, parse_args,
            verbose=verbose,
            root_namespace='RE',
            category_prefix='/CommonLibSF',
        )

        if verbose:
            print('Building vtable structs...')
        vtable_structs = build_vtable_structs(structs, category_prefix='/CommonLibSF')
        inject_vtable_fields(structs, vtable_structs)
        flatten_structs(structs)
        apply_secondary_vtable_typing(structs, vtable_structs)

        if verbose:
            print('  enums:    {}'.format(len(enums)))
            print('  structs:  {}'.format(len(structs)))
            print('  vtables:  {}'.format(len(vtable_structs)))
        return enums, structs, vtable_structs, template_source
    except (Exception, SystemExit) as e:
        # clang_types.collect_types() calls sys.exit() when clang.exe isn't
        # on PATH, so catch SystemExit too.
        print('WARNING: CommonLibSF AST parse failed ({}: {})'.format(type(e).__name__, e))
        print('         Falling back to labels-only output (no struct/enum types).')
        return {}, {}, {}, ''


def main():
    print('=== CommonLibSF -> Ghidra import script ===')
    print('PROJECT_DIR        =', PROJECT_DIR)
    print('COMMONLIB_INCLUDE  =', COMMONLIB_INCLUDE)
    print('STARFIELD_H        =', STARFIELD_H)
    print('OUTPUT_DIR         =', OUTPUT_DIR)
    print()

    if not os.path.isfile(STARFIELD_H):
        print('ERROR: {} not found.  Run `git submodule update --init` first.'.format(
            STARFIELD_H))
        sys.exit(1)

    # 1. Address library
    addr_lib = AddressLibrary()
    addr_lib.load_all(os.path.join(PROJECT_DIR, 'addresslibrary'))
    if not addr_lib.sf_db:
        print('ERROR: Starfield address library not loaded.  Expected '
              '`addresslibrary/starfield/versionlib-1-16-236-0.bin`.')
        sys.exit(1)
    print('Address library entries: {:,}'.format(len(addr_lib.sf_db)))

    # 2. Manifest symbol scan
    func_syms, label_syms = collect_id_symbols(RE_INCLUDE, addr_lib, verbose=True)

    # 3. Type extraction via libclang (best-effort)
    enums, structs, vtable_structs, template_source = _try_clang_types(verbose=True)

    # 4. Assemble SYMBOLS array
    symbols      = _make_symbols(func_syms, label_syms)
    symbols_json = _json.dumps(symbols, separators=(',', ':'))

    n_func  = sum(1 for s in symbols if s['t'] == 'func')
    n_label = sum(1 for s in symbols if s['t'] == 'label')
    print('\nSymbols: {} total ({} funcs, {} labels)'.format(
        len(symbols), n_func, n_label))

    # 5. Generate the Ghidra Jython import script
    from ghidra_import_gen import generate_script
    output_path = os.path.join(OUTPUT_DIR, 'CommonLibImport_SF.py')
    n_enums, n_structs = generate_script(
        enums, structs, vtable_structs,
        output_path,
        version='sf',
        symbols_json=symbols_json,
        fallback_symbols_json='[]',
        template_source=template_source,
        project_name='CommonLibSF',
    )
    print('\nWrote {}'.format(output_path))
    print('  {} enums, {} structs, {} vtable structs, {} symbols'.format(
        n_enums, n_structs, len(vtable_structs), len(symbols)))


if __name__ == '__main__':
    main()
