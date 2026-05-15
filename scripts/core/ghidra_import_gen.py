"""Ghidra import script generator.

Takes processed C++ type data (enums, structs, vtable info) and symbol tables,
then generates a self-contained Jython script that imports everything into Ghidra's
Data Type Manager and Symbol Table.

The generated script handles:
  - Enum, struct, and vtable type creation in Ghidra's DTM
  - Function symbol labeling and disassembly at known addresses
  - Signature application via structured pipeline types (FunctionDefinitionDataType)
    or C prototype parsing (CParserUtils) with type simplification fallback
  - Virtual function naming by walking VTABLE label addresses
  - Fallback symbol application (PDB / AE rename / IDA NAME script) for
    unnamed functions

This module is game/project-agnostic. All project-specific logic (source parsing,
address libraries, fallback-name loading, relocation scanning) lives in the
caller.

Public API:
  build_vtable_structs()         - build primary + secondary vtable descriptors
                                   from the virtual class hierarchy
  inject_vtable_fields()         - prepend __vftable pointers to virtual structs
  flatten_structs()              - expand base class fields into derived structs
  apply_secondary_vtable_typing() - retype non-zero-offset __vftable_<base>
                                    fields to per-class secondary vtable structs
                                    (multi-inheritance)
  generate_script()              - emit the Ghidra import script
"""

from __future__ import annotations

import json
import os
import re
import struct
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Type-string utilities
# ---------------------------------------------------------------------------

def _type_str_size(type_str: str) -> int:
    """Estimate byte size from a pipeline type descriptor string."""
    sizes = {
        'bool': 1, 'i8': 1, 'u8': 1,
        'i16': 2, 'u16': 2,
        'i32': 4, 'u32': 4, 'f32': 4,
        'i64': 8, 'u64': 8, 'f64': 8,
        'ptr': 8, 'void': 0,
    }
    if type_str in sizes:
        return sizes[type_str]
    if type_str.startswith('bytes:'):
        return int(type_str[6:])
    if type_str.startswith('arr:'):
        rest = type_str[4:]
        last = rest.rfind(':')
        if last >= 0 and rest[last+1:].isdigit():
            count = int(rest[last+1:])
            elem_size = _type_str_size(rest[:last])
            return elem_size * count
        return 0
    if type_str.startswith('enum:'):
        return 4
    if type_str.startswith('struct:'):
        return 8
    return 0


# ---------------------------------------------------------------------------
# Base-class name resolution
# ---------------------------------------------------------------------------

def _resolve_base(by_name: dict, name: str):
    """Look up a base class by name, handling namespace prefix and template types."""
    st = by_name.get(name)
    if st:
        return st
    # Try stripping root namespace prefix (e.g. RE::Actor -> Actor)
    idx = name.find('::')
    if idx >= 0 and '<' not in name[:idx]:
        st = by_name.get(name[idx + 2:])
        if st:
            return st
    if '<' not in name:
        short = name.split('::')[-1]
        st = by_name.get(short)
        if st:
            return st
    return None


# ---------------------------------------------------------------------------
# Vtable struct building
# ---------------------------------------------------------------------------

def build_vtable_structs(structs: dict) -> dict:
    """Build vtable type descriptors from virtual class hierarchies.

    Returns dict: full_name -> vtable descriptor dict.
    """
    by_name = {}
    for st in structs.values():
        by_name[st['full_name']] = st
        by_name[st['name']] = st

    memo = {}
    sig_memo = {}

    def _primary_base_st(st):
        pdb_bases = st.get('pdb_bases', [])
        if pdb_bases:
            primary_name, primary_off = pdb_bases[0]
            if primary_off == 0:
                return _resolve_base(by_name, primary_name)
        else:
            for base_ref in st.get('bases', []):
                return _resolve_base(by_name, base_ref)
        return None

    def get_slots(full_name, depth=0):
        if depth > 20:
            return {}
        if full_name in memo:
            return memo[full_name]
        st = by_name.get(full_name)
        if not st:
            memo[full_name] = {}
            return {}
        memo[full_name] = {}
        slots = {}
        bst = _primary_base_st(st)
        if bst:
            slots.update(get_slots(bst['full_name'], depth + 1))
        for mname, vbaseoff in st.get('vfuncs', []):
            if vbaseoff >= 0 and mname:
                slots[vbaseoff] = mname
        memo[full_name] = slots
        return slots

    def get_sigs(full_name, depth=0):
        if depth > 20:
            return {}
        if full_name in sig_memo:
            return sig_memo[full_name]
        st = by_name.get(full_name)
        if not st:
            sig_memo[full_name] = {}
            return {}
        sig_memo[full_name] = {}
        sigs = {}
        bst = _primary_base_st(st)
        if bst:
            sigs.update(get_sigs(bst['full_name'], depth + 1))
        sigs.update(st.get('vmethods', {}))
        sig_memo[full_name] = sigs
        return sigs

    vtable_structs = {}
    secondary_count = 0
    for st in structs.values():
        if not st.get('has_vtable') and not st.get('vfuncs'):
            continue
        named = get_slots(st['full_name'])
        if not named:
            continue
        max_off = max(named.keys())
        vtbl_size = max_off + 8
        all_slots = dict(named)
        if vtbl_size <= 0x4000:
            for off in range(0, vtbl_size, 8):
                if off not in all_slots:
                    all_slots[off] = 'fn_{:03X}'.format(off)
        sigs = get_sigs(st['full_name'])
        sorted_slots = []
        for off, name in sorted(all_slots.items()):
            sig = sigs.get(name)
            sorted_slots.append((off, name, sig[0] if sig else None, sig[1] if sig else None))
        vname = st['name'] + '_vtbl'
        vtable_structs[st['full_name']] = {
            'name': vname,
            'class_full_name': st['full_name'],
            'category': st['category'],
            'slots': sorted_slots,
            'size': vtbl_size,
        }

        # --- Secondary vtables from clang -fdump-vtable-layouts (multi-inheritance) ---
        secondaries = st.get('secondary_vtables') or {}
        if secondaries:
            sec_names = {}  # offset -> generated struct name
            for offset, slot_list in secondaries.items():
                if not slot_list:
                    continue
                sec_named = {sidx * 8: mname for sidx, mname in slot_list}
                sec_max = max(sec_named.keys())
                sec_size = sec_max + 8
                sec_all = dict(sec_named)
                if sec_size <= 0x4000:
                    for off in range(0, sec_size, 8):
                        if off not in sec_all:
                            sec_all[off] = 'fn_{:03X}'.format(off)
                sec_sorted = []
                for off, sname in sorted(sec_all.items()):
                    sig = sigs.get(sname)
                    sec_sorted.append((off, sname,
                                       sig[0] if sig else None,
                                       sig[1] if sig else None))
                sec_struct_name = '{}_vtbl_{}'.format(st['name'], offset)
                key = '{}|secondary|{}'.format(st['full_name'], offset)
                vtable_structs[key] = {
                    'name': sec_struct_name,
                    'class_full_name': st['full_name'],
                    'category': st['category'],
                    'slots': sec_sorted,
                    'size': sec_size,
                }
                sec_names[offset] = sec_struct_name
                secondary_count += 1
            if sec_names:
                st['secondary_struct_names'] = sec_names

    if secondary_count:
        print('Built {} vtable structs ({} secondary)'.format(
            len(vtable_structs), secondary_count))
    else:
        print('Built {} vtable structs'.format(len(vtable_structs)))
    return vtable_structs


def apply_secondary_vtable_typing(structs: dict) -> int:
    """Rewrite each class's flattened ``__vftable_<base>`` field types so they
    point at the per-class secondary vtable struct generated for that subobject
    offset, instead of inheriting the base class's primary vtable struct type.

    Must be called AFTER ``flatten_structs`` so the secondary ``__vftable_<base>``
    fields exist at their absolute offsets.  Each struct must already have
    ``secondary_struct_names = {offset: struct_name}`` populated (done by
    ``build_vtable_structs`` from clang ``-fdump-vtable-layouts`` data).
    """
    rewrites = 0
    for st in structs.values():
        sec_map = st.get('secondary_struct_names') or {}
        if not sec_map:
            continue
        for f in st.get('fields', []):
            if not f.get('name', '').startswith('__vftable'):
                continue
            offset = f.get('offset', 0)
            if offset == 0:
                continue
            sec_name = sec_map.get(offset)
            if sec_name:
                f['type'] = 'vtblptr:' + sec_name
                rewrites += 1
    if rewrites:
        print('Retyped {} secondary vtable pointer fields'.format(rewrites))
    return rewrites


def inject_vtable_fields(structs: dict, vtable_structs: dict) -> None:
    """Prepend __vftable pointer fields to virtual structs missing offset-0 fields."""
    count = 0
    for st in structs.values():
        if not st.get('has_vtable') and not st.get('vfuncs'):
            continue
        if st['size'] < 8:
            continue
        if any(f['offset'] == 0 for f in st['fields']):
            continue
        vt = vtable_structs.get(st['full_name'])
        vtbl_type = ('vtblptr:' + vt['name']) if vt else 'ptr'
        st['fields'].insert(0, {
            'name': '__vftable',
            'type': vtbl_type,
            'offset': 0,
            'size': 8,
        })
        count += 1
    print('Injected vtable pointer fields into {} structs'.format(count))


def flatten_structs(structs: dict) -> None:
    """Expand base class fields into derived structs.

    Uses pdb_bases ([(base_name, base_offset)]) when available for accurate
    multi-base placement; falls back to assuming first base starts at offset 0.
    """
    by_name = {}
    for st in structs.values():
        by_name[st['full_name']] = st
        by_name[st['name']] = st

    memo = {}

    def get_flat(full_name, depth=0):
        if depth > 20:
            return []
        if full_name in memo:
            return memo[full_name]
        st = by_name.get(full_name)
        if not st:
            memo[full_name] = []
            return []
        memo[full_name] = []
        combined = {}

        def _field_key(f, offset=None):
            off = offset if offset is not None else f['offset']
            if f['type'].startswith('bf:'):
                return ('bf', off, f['type'])
            return off

        pdb_bases = st.get('pdb_bases', [])
        if pdb_bases:
            for base_name, base_off in pdb_bases:
                base_st = _resolve_base(by_name, base_name)
                if not base_st:
                    continue
                for f in get_flat(base_st['full_name'], depth + 1):
                    abs_off = base_off + f['offset']
                    key = _field_key(f, abs_off)
                    if key not in combined:
                        field_copy = dict(f, offset=abs_off)
                        if f['name'] == '__vftable' and base_off > 0:
                            field_copy['name'] = '__vftable_' + base_st['name']
                        combined[key] = field_copy
        else:
            for base_ref in st.get('bases', []):
                base_st = _resolve_base(by_name, base_ref)
                if not base_st or base_st['size'] <= 1:
                    continue
                for f in get_flat(base_st['full_name'], depth + 1):
                    key = _field_key(f)
                    if key not in combined:
                        combined[key] = f
                break

        for f in st['fields']:
            combined[_field_key(f)] = f
        flat = sorted(combined.values(), key=lambda f: (f['offset'], f['type']))
        for i in range(len(flat) - 1):
            end = flat[i]['offset'] + flat[i]['size']
            if end > flat[i + 1]['offset']:
                flat[i] = dict(flat[i], size=flat[i + 1]['offset'] - flat[i]['offset'])
        memo[full_name] = flat
        return flat

    for st in structs.values():
        st['fields'] = get_flat(st['full_name'])

    gained = sum(1 for st in structs.values() if len(st['fields']) > 0)
    print('Flattening: {} structs have field data after inheritance expansion'.format(gained))


# ---------------------------------------------------------------------------
# Ghidra script template (embedded Jython)
# ---------------------------------------------------------------------------
#
# These are triple-quoted strings written verbatim into the generated .py file.
# Single backslashes (e.g. \b, \s, \w) are regex escapes in the OUTPUT script,
# not in this Python source — the triple-quote preserves them as-is.
#

GHIDRA_SCRIPT_HEADER = '''\
# Ghidra import script: C++ types + symbols
# Generated by ghidra_import_gen.py
# Run in Ghidra via Script Manager
#
# @category Import
# @description Import C++ type definitions and symbol names

from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.util.cparser.C import CParserUtils
from ghidra.program.model.data import (
    StructureDataType, EnumDataType, ArrayDataType, PointerDataType,
    CategoryPath, DataTypeConflictHandler,
    ByteDataType, WordDataType, DWordDataType, QWordDataType,
    CharDataType, BooleanDataType, VoidDataType,
    FloatDataType, DoubleDataType,
    ShortDataType, IntegerDataType, LongLongDataType,
    UnsignedShortDataType, UnsignedIntegerDataType, UnsignedLongLongDataType,
    FunctionDefinitionDataType, ParameterDefinitionImpl,
)
import re
import struct

dtm = currentProgram.getDataTypeManager()
CONFLICT = DataTypeConflictHandler.REPLACE_HANDLER

created = {}  # full_name -> DataType

_VOID  = VoidDataType()
_BYTE  = ByteDataType()
_PTR   = PointerDataType()
_BOOL  = BooleanDataType()
_I16   = ShortDataType()
_U16   = UnsignedShortDataType()
_I32   = IntegerDataType()
_U32   = UnsignedIntegerDataType()
_I64   = LongLongDataType()
_U64   = UnsignedLongLongDataType()
_F32   = FloatDataType()
_F64   = DoubleDataType()

def get_builtin(type_str):
    if type_str == 'void': return _VOID
    if type_str == 'bool': return _BOOL
    if type_str == 'i8':   return _BYTE
    if type_str == 'u8':   return _BYTE
    if type_str == 'i16':  return _I16
    if type_str == 'u16':  return _U16
    if type_str == 'i32':  return _I32
    if type_str == 'u32':  return _U32
    if type_str == 'i64':  return _I64
    if type_str == 'u64':  return _U64
    if type_str == 'f32':  return _F32
    if type_str == 'f64':  return _F64
    if type_str == 'ptr':  return _PTR
    return None

def _resolve_struct_name(name):
    """Look up a struct/class name in 'created', handling template instantiations."""
    if '<' in name:
        alias = TEMPLATE_TYPE_MAP.get(name)
        if alias:
            return created.get(alias)
        # Some template instantiations are emitted directly under their full name
        return created.get(name)
    return created.get(name) or created.get(name.split('::')[-1])

def resolve_type(type_str):
    b = get_builtin(type_str)
    if b: return b
    if type_str.startswith('ptr:struct:'):
        name = type_str[11:]
        inner = _resolve_struct_name(name)
        return dtm.getPointer(inner, 8) if inner else _PTR
    if type_str.startswith('ptr:enum:'):
        name = type_str[9:]
        inner = created.get(name) or created.get(name.split('::')[-1])
        return dtm.getPointer(inner, 8) if inner else _PTR
    if type_str.startswith('ptr:'):
        inner = get_builtin(type_str[4:]) or resolve_type(type_str[4:])
        if inner: return dtm.getPointer(inner, 8)
    if type_str.startswith('ptr'): return _PTR
    if type_str.startswith('bytes:'):
        n = int(type_str[6:])
        if n == 1: return _BYTE
        if n == 2: return _I16
        if n == 4: return _I32
        if n == 8: return _I64
        return ArrayDataType(_BYTE, n, 1) if n > 1 else _BYTE
    if type_str.startswith('arr:'):
        rest = type_str[4:]
        last = rest.rfind(':')
        if last >= 0 and rest[last+1:].isdigit():
            count = int(rest[last+1:])
            elem = resolve_type(rest[:last])
            if elem and count > 0:
                return ArrayDataType(elem, count, elem.getLength())
        return None
    if type_str.startswith('enum:'):
        name = type_str[5:]
        return created.get(name) or created.get(name.split('::')[-1])
    if type_str.startswith('struct:'):
        name = type_str[7:]
        return _resolve_struct_name(name)
    if type_str.startswith('vtblptr:'):
        name = type_str[8:]
        vtbl_dt = created.get('vtbl:' + name)
        if vtbl_dt:
            return dtm.getPointer(vtbl_dt, 8)
        return _PTR
    return None

def make_padding(size):
    if size == 1: return _BYTE
    return ArrayDataType(_BYTE, size, 1)


def apply_structured_sig(sd, func_name, addr, fm):
    """Apply a structured signature using FunctionDefinitionDataType.

    sd is [ret_type, [[pname, ptype], ...], is_static] with pipeline type
    descriptors that resolve_type() understands.  Bypasses CParserUtils
    entirely — no C parsing errors.
    """
    ret_pipeline, params_list, is_static = sd
    simple_name = func_name.split('::')[-1] if '::' in func_name else func_name
    fdef = FunctionDefinitionDataType(CategoryPath('/'), simple_name, dtm)
    ret_dt = resolve_type(ret_pipeline)
    if ret_dt:
        fdef.setReturnType(ret_dt)
    param_defs = []
    if '::' in func_name and not is_static:
        class_name = func_name.rsplit('::', 1)[0].split('::')[-1]
        this_dt = created.get(class_name)
        this_ptr = dtm.getPointer(this_dt, 8) if this_dt else _PTR
        param_defs.append(ParameterDefinitionImpl('this', this_ptr, ''))
    for pname, ptype in params_list:
        pdt = resolve_type(ptype) or _PTR
        param_defs.append(ParameterDefinitionImpl(pname, pdt, ''))
    if param_defs:
        fdef.setArguments(param_defs)
    cmd = ApplyFunctionSignatureCmd(addr, fdef, SourceType.USER_DEFINED, True, False)
    cmd.applyTo(currentProgram)
    return True


def convert_sig_to_ghidra(sig, func_name):
    """Convert a C++ signature to a Ghidra-compatible C prototype."""
    if not sig or sig == 'func_t':
        return None

    if 'RELOCATION_ID' in sig or 'func_t>' in sig or 'decltype' in sig:
        return None
    if ')(' in sig:
        return None
    if ':(' in sig:
        return None

    is_static = bool(re.search(r'\\bstatic\\b', sig))

    sig = ' '.join(sig.split())

    while True:
        _m_td = re.match(r'\\s*typedef\\s+[^;]+;\\s*', sig)
        if not _m_td: break
        sig = sig[_m_td.end():]

    sig = re.sub(r'^//\\s*[0-9A-Fa-f]+\\s*', '', sig)
    sig = re.sub(r'^//\\s*', '', sig)
    sig = re.sub(r'\\s*//[^\\n]*', '', sig)
    sig = re.sub(r'#\\w+\\b[^\\n]*', '', sig)
    sig = re.sub(r'\\b(?:public|private|protected)\\s*:\\s*', '', sig)
    sig = re.sub(r'\\boverride\\s+\\w+\\s*\\([^)]*\\)\\s*', '', sig)
    sig = re.sub(r'\\bRUNTIME_DATA_CONTENT\\b', '', sig)
    sig = re.sub(r'!\\w+\\([^)]*\\)\\s+', '', sig)

    sig = sig.replace('[[nodiscard]]', '')
    sig = re.sub(r'\\bstatic\\b', '', sig)
    sig = re.sub(r'\\bvirtual\\b', '', sig)
    sig = sig.strip()

    candidates = []
    depth = 0
    for i, c in enumerate(sig):
        if c == '<': depth += 1
        elif c == '>': depth -= 1
        elif c == '(' and depth == 0:
            candidates.append(i)

    if not candidates:
        return None

    paren_idx = None
    for idx in reversed(candidates):
        before = sig[:idx].rstrip()
        if before and re.search(r'[\\w*&]\\s*$', before):
            stripped_ret = before.strip()
            if stripped_ret and not re.match(
                r'^(if|for|while|switch|return|override|namespace|class|struct)\\b',
                stripped_ret.split()[-1] if stripped_ret.split() else ''
            ):
                paren_idx = idx
                break

    if paren_idx is None or paren_idx == 0:
        return None

    ret_type_raw = sig[:paren_idx].strip()
    params = sig[paren_idx:]

    ret_type = ret_type_raw
    for pat in [r'.*\\b(?:public|private|protected)\\s*:\\s*',
                r'.*\\b(?:override)\\s+\\w+\\s*\\([^)]*\\)\\s*',
                r'.*//[^/]*\\s+',
                r'.*#\\w+[^(]*\\s+',
                r'.*!\\w+\\([^)]*\\)\\s+',
                r'.*\\bnamespace\\s+\\w+\\s*\\{\\s*',
                r'.*\\bmembers\\b\\s*']:
        m = re.match(pat, ret_type, re.DOTALL)
        if m: ret_type = ret_type[m.end():]

    ret_type = ret_type.strip()
    if not ret_type:
        return None

    def simplify_type(t, is_return=False):
        t = re.sub(r'\\s*=\\s*[^,)]*$', '', t)
        t = t.replace('std::uint64_t', 'ulonglong')
        t = t.replace('std::int64_t', 'longlong')
        t = t.replace('std::uint32_t', 'uint')
        t = t.replace('std::int32_t', 'int')
        t = t.replace('std::uint16_t', 'ushort')
        t = t.replace('std::int16_t', 'short')
        t = t.replace('std::uint8_t', 'uchar')
        t = t.replace('std::int8_t', 'char')
        t = t.replace('std::size_t', 'ulonglong')
        t = t.replace('std::ptrdiff_t', 'longlong')
        t = re.sub(r'\\buint64_t\\b', 'ulonglong', t)
        t = re.sub(r'\\bint64_t\\b', 'longlong', t)
        t = re.sub(r'\\buint32_t\\b', 'uint', t)
        t = re.sub(r'\\bint32_t\\b', 'int', t)
        t = re.sub(r'\\buint16_t\\b', 'ushort', t)
        t = re.sub(r'\\bint16_t\\b', 'short', t)
        t = re.sub(r'\\buint8_t\\b', 'uchar', t)
        t = re.sub(r'\\bint8_t\\b', 'char', t)
        t = re.sub(r'\\bsize_t\\b', 'ulonglong', t)
        t = re.sub(r'\\bresult\\b', 'int', t)
        t = re.sub(r'\\bhours\\b', 'longlong', t)
        t = re.sub(r'\\bminutes\\b', 'longlong', t)
        t = re.sub(r'\\bseconds\\b', 'longlong', t)
        t = re.sub(r'\\bErrorCode\\b', 'uint', t)
        t = re.sub(r'\\bmbstate_t\\b', 'void', t)
        t = re.sub(r'\\bva_list\\b', 'void *', t)
        t = re.sub(r'\\bchar16_t\\b', 'ushort', t)
        t = re.sub(r'\\bchar32_t\\b', 'uint', t)
        t = re.sub(r'\\bwchar_t\\b', 'ushort', t)
        t = re.sub(r'\\bconst\\b\\s*', '', t)
        t = re.sub(r'(\\w[\\w:<>]*)\\s*&', r'\\1 *', t)
        for _ in range(5):
            prev = t
            t = re.sub(r'\\w[\\w:]*<[^<>]*>\\s*\\*', 'void *', t)
            t = re.sub(r'\\w[\\w:]*<[^<>]*>', 'void', t)
            if t == prev: break
        t = re.sub(r'Args\\s*\\.\\.\\..*', '', t)
        if not is_return:
            t = re.sub(r'\\[.*?\\]', '', t)
        t = re.sub(r'\\w+::', '', t)
        return t.strip()

    ret_type = simplify_type(ret_type, is_return=True)
    if not ret_type:
        return None
    parts = ret_type.split()
    if len(parts) > 1 and parts[-1] not in ('*',) and not parts[-1].endswith('*'):
        ret_type = ' '.join(parts[:-1])

    params_inner = params[1:-1].strip() if params.endswith(')') else params[1:].rstrip(')').strip()

    if params_inner == '' or params_inner == 'void':
        ghidra_params = 'void'
    else:
        param_list = []
        current = ''; depth = 0
        for c in params_inner:
            if c == '<': depth += 1
            elif c == '>': depth -= 1
            elif c == ',' and depth == 0:
                param_list.append(current.strip()); current = ''; continue
            current += c
        if current.strip(): param_list.append(current.strip())

        ghidra_params_list = []
        for p in param_list:
            p = simplify_type(p)
            if not p: continue
            tokens = p.split()
            if len(tokens) == 2 and tokens[0] == 'void' and '*' not in tokens[1]:
                p = 'void * ' + tokens[1]
            if tokens:
                last = tokens[-1].rstrip('*')
                if last in ('int','uint','float','double','bool','void','char',
                            'short','long','uchar','ushort','ulonglong','longlong') or last.endswith('*'):
                    p = p + ' param' + str(len(ghidra_params_list))
            ghidra_params_list.append(p)

        ghidra_params = ', '.join(ghidra_params_list) if ghidra_params_list else 'void'

    simple_name = func_name.split('::')[-1] if '::' in func_name else func_name

    if '::' in func_name and not is_static:
        class_name = func_name.rsplit('::', 1)[0]
        class_name_simple = class_name.split('::')[-1] if '::' in class_name else class_name
        if class_name_simple and created.get(class_name_simple):
            this_type = class_name_simple
        else:
            this_type = 'void'
        this_param = this_type + ' * this'
        if ghidra_params == 'void':
            ghidra_params = this_param
        else:
            ghidra_params = this_param + ', ' + ghidra_params

    return ret_type + ' ' + simple_name + '(' + ghidra_params + ')'


_SAFE_TYPES = {
    'void', 'bool', 'char', 'short', 'int', 'long', 'float', 'double',
    'uchar', 'ushort', 'uint', 'ulong', 'longlong', 'ulonglong',
    'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8',
    'byte', 'word', 'dword', 'qword', 'pointer', 'unsigned', 'signed',
}

def sanitize_unknown_types(proto):
    """Replace unknown types with void* for Ghidra parse fallback."""
    m = re.match(r'(.*?)\\s+(\\w+)\\s*\\((.*)\\)$', proto)
    if not m: return proto
    ret, name, params = m.group(1), m.group(2), m.group(3)

    def sanitize_token(t):
        t = t.strip()
        if not t or t == 'void': return t
        parts = t.split()
        base = parts[0].rstrip('*')
        if base.lower() in _SAFE_TYPES: return t
        is_ptr = '*' in t
        if is_ptr:
            star_count = t.count('*')
            stars = ' ' + '*' * star_count
            param_name = ''
            if len(parts) > 1 and '*' not in parts[-1]:
                param_name = ' ' + parts[-1]
            return 'void' + stars + param_name
        else:
            if len(parts) > 1 and parts[-1].isidentifier():
                return 'void * ' + parts[-1]
            return 'void *'

    ret_base = ret.rstrip('*').rstrip().split()[-1] if ret.split() else ret
    if ret_base.lower() not in _SAFE_TYPES:
        if '*' in ret: ret = 'void ' + '*' * ret.count('*')
        else: ret = 'void *'

    if params.strip() == 'void':
        safe_params = 'void'
    else:
        safe_params = ', '.join(sanitize_token(p.strip()) for p in params.split(','))

    return ret + ' ' + name + '(' + safe_params + ')'

'''

GHIDRA_SCRIPT_FOOTER = '''\

def run():
    tx_types = dtm.startTransaction('Import types')
    try:
        _import_types()
    finally:
        dtm.endTransaction(tx_types, True)

    tx_syms = currentProgram.startTransaction('Symbol import')
    try:
        _import_symbols()
        _import_vtable_names()
        _import_fallback_symbols()
    finally:
        currentProgram.endTransaction(tx_syms, True)

    print('All passes complete.')


def _import_types():
    monitor.setMessage('Creating enums...')
    for en in ENUMS:
        name, size, category, values = en
        e = EnumDataType(CategoryPath(category), name, size)
        for vname, vval in values:
            try:
                e.add(vname, vval)
            except Exception:
                e.add(vname + '_', vval)
        dt = dtm.addDataType(e, CONFLICT)
        created[name] = dt
        created[category + '/' + name] = dt
        ns = '::'.join(category.strip('/').split('/')[1:])
        if ns:
            created[ns + '::' + name] = dt
    print('Created {} enums'.format(len(ENUMS)))

    monitor.setMessage('Creating vtable structs...')
    for vt in VTABLES:
        vname, class_full_name, vtbl_size, category, slots = vt
        s = StructureDataType(CategoryPath(category), vname, vtbl_size)
        for slot_off, slot_name, slot_ret, slot_params in slots:
            field_name = slot_name.replace('~', '_dtor_') if slot_name.startswith('~') else slot_name
            if slot_off + 8 <= vtbl_size:
                try:
                    if slot_ret is not None and slot_params is not None:
                        fdef = FunctionDefinitionDataType(CategoryPath(category), field_name + '_t', dtm)
                        ret_dt = resolve_type(slot_ret)
                        if ret_dt:
                            fdef.setReturnType(ret_dt)
                        if slot_params:
                            param_defs = []
                            for pname, ptype in slot_params:
                                pdt = resolve_type(ptype) or _PTR
                                param_defs.append(ParameterDefinitionImpl(pname, pdt, ''))
                            fdef.setArguments(param_defs)
                        fptr = dtm.getPointer(dtm.addDataType(fdef, CONFLICT), 8)
                        s.replaceAtOffset(slot_off, fptr, 8, field_name, '')
                    else:
                        s.replaceAtOffset(slot_off, _PTR, 8, field_name, '')
                except Exception:
                    pass
        dt = dtm.addDataType(s, CONFLICT)
        created['vtbl:' + vname] = dt
    print('Created {} vtable structs'.format(len(VTABLES)))

    monitor.setMessage('Creating struct shells...')
    for st in STRUCTS:
        name, size, category, fields, bases, has_vtable = st
        s = StructureDataType(CategoryPath(category), name, size)
        dt = dtm.addDataType(s, CONFLICT)
        created[name] = dt
        created[category + '/' + name] = dt
        ns = '::'.join(category.strip('/').split('/')[1:])
        if ns:
            created[ns + '::' + name] = dt
    print('Created {} struct shells'.format(len(STRUCTS)))

    monitor.setMessage('Filling struct fields...')
    filled = 0
    for st in STRUCTS:
        name, size, category, fields, bases, has_vtable = st
        s = dtm.getDataType(CategoryPath(category), name)
        if not s:
            continue
        for field in fields:
            fname, ftype_str, foffset, fsize = field
            if ftype_str.startswith('bf:'):
                parts = ftype_str.split(':')
                bf_bit_offset = int(parts[1])
                bf_width = int(parts[2])
                bf_bw = 4
                bf_base = _U32
                for _bw, _bd in [(1, _BYTE), (2, _U16), (4, _U32), (8, _U64)]:
                    _bits = _bw * 8
                    _sb = (bf_bit_offset // _bits) * _bw
                    if bf_bit_offset % _bits + bf_width <= _bits and _sb + _bw <= size:
                        bf_bw = _bw
                        bf_base = _bd
                        break
                storage_byte = (bf_bit_offset // (bf_bw * 8)) * bf_bw
                bit_in_storage = bf_bit_offset % (bf_bw * 8)
                try:
                    s.insertBitFieldAt(storage_byte, bf_bw, bit_in_storage, bf_base, bf_width, fname, '')
                except Exception:
                    pass
                continue
            if fsize <= 0 or foffset + fsize > size:
                continue
            dt_field = resolve_type(ftype_str)
            if dt_field and dt_field.getLength() == fsize:
                use_dt = dt_field
                use_name = fname
            else:
                use_dt = make_padding(fsize)
                use_name = fname + '_raw'
            try:
                s.replaceAtOffset(foffset, use_dt, fsize, use_name, '')
            except Exception:
                pass
        filled += 1
    print('Filled {} structs'.format(filled))


def _import_symbols():
    version_key = 's' if VERSION == 'se' else 'a'
    symbol_table = currentProgram.getSymbolTable()
    base_addr = currentProgram.getImageBase()
    fm = currentProgram.getFunctionManager()

    print('Target version: ' + VERSION.upper())
    print('Applying ' + str(len(SYMBOLS)) + ' symbols...')

    count_sym = 0; count_func = 0; count_sig = 0; count_sig_fail = 0
    used_names_at_addr = {}
    name_occurrence_count = {}

    for i, s in enumerate(SYMBOLS):
        off = s.get(version_key)
        if not off: continue
        off = int(off)

        addr = base_addr.add(off)
        sname = s['n']

        if addr not in used_names_at_addr:
            used_names_at_addr[addr] = set()
        if sname in used_names_at_addr[addr]:
            continue

        if sname in name_occurrence_count:
            name_occurrence_count[sname] += 1
            final_name = sname + '_' + str(name_occurrence_count[sname])
        else:
            name_occurrence_count[sname] = 0
            final_name = sname

        try:
            symbol_table.createLabel(addr, final_name, SourceType.USER_DEFINED)
            used_names_at_addr[addr].add(sname)
            count_sym += 1
            if s['t'] == 'label':
                cu = currentProgram.getListing().getCodeUnitAt(addr)
                if cu:
                    parts = []
                    se_id = s.get('si')
                    ae_id = s.get('ai')
                    if se_id and ae_id:
                        parts.append('RELOCATION_ID(' + str(se_id) + ', ' + str(ae_id) + ')')
                    elif se_id:
                        parts.append('REL::ID(' + str(se_id) + ')')
                    elif ae_id:
                        parts.append('REL::ID(' + str(ae_id) + ')')
                    if final_name.startswith('RTTI_'):
                        parts.append('Source: ' + PROJECT_NAME + ' (Offsets_RTTI.h)')
                    elif final_name.startswith('VTABLE_'):
                        parts.append('Source: ' + PROJECT_NAME + ' (Offsets_VTABLE.h)')
                    elif s.get('src'):
                        parts.append('Source: ' + s['src'])
                    if parts:
                        cu.setComment(0, '\\n'.join(parts))
        except: pass

        if s['t'] == 'func':
            try:
                f = fm.getFunctionAt(addr)
                if not f:
                    cmd = DisassembleCommand(addr, None, True)
                    cmd.applyTo(currentProgram)
                    f = createFunction(addr, final_name)

                if f:
                    curr_name = f.getName()
                    if curr_name.startswith('FUN_') or curr_name.startswith('sub_'):
                        f.setName(final_name, SourceType.USER_DEFINED)

                    comment_parts = []
                    se_id = s.get('si')
                    ae_id = s.get('ai')
                    if se_id and ae_id:
                        comment_parts.append('RELOCATION_ID(' + str(se_id) + ', ' + str(ae_id) + ')')
                    elif se_id:
                        comment_parts.append('REL::ID(' + str(se_id) + ')')
                    elif ae_id:
                        comment_parts.append('REL::ID(' + str(ae_id) + ')')
                    src = s.get('src', '')
                    if src == PROJECT_NAME:
                        comment_parts.append('Source: ' + PROJECT_NAME + ' headers')
                    elif src == 'skyrimae.rename':
                        comment_parts.append('Source: AE rename database (fallback)')
                    elif src:
                        comment_parts.append('Source: ' + src)
                    if comment_parts:
                        cu = currentProgram.getListing().getCodeUnitAt(addr)
                        if cu:
                            cu.setComment(0, '\\n'.join(comment_parts))

                    sd = s.get('sd')
                    sig = s.get('sig', '')
                    if sd:
                        try:
                            apply_structured_sig(sd, final_name, addr, fm)
                            count_sig += 1
                        except:
                            count_sig_fail += 1
                    elif sig:
                        proto = convert_sig_to_ghidra(sig, final_name)
                        if proto:
                            applied = False
                            try:
                                func_def = CParserUtils.parseSignature(None, currentProgram, proto, True)
                                if func_def:
                                    cmd = ApplyFunctionSignatureCmd(addr, func_def, SourceType.USER_DEFINED, True, False)
                                    cmd.applyTo(currentProgram)
                                    applied = True
                            except: pass
                            if not applied:
                                proto_safe = sanitize_unknown_types(proto)
                                if proto_safe != proto:
                                    try:
                                        func_def = CParserUtils.parseSignature(None, currentProgram, proto_safe, True)
                                        if func_def:
                                            cmd = ApplyFunctionSignatureCmd(addr, func_def, SourceType.USER_DEFINED, True, False)
                                            cmd.applyTo(currentProgram)
                                            applied = True
                                    except: pass
                            if applied:
                                count_sig += 1
                            else:
                                count_sig_fail += 1
                                if count_sig_fail <= 20:
                                    print('SIG FAIL: ' + proto[:120])
                    count_func += 1
            except: pass

        if i % 5000 == 0 and i > 0:
            print('Progress: ' + str(i) + ' symbols processed...')

    print('Labels: ' + str(count_sym) + ', Functions: ' + str(count_func))
    print('Signatures applied: ' + str(count_sig) + ', failed: ' + str(count_sig_fail))


def _build_rva_to_id():
    import base64 as _b64
    rva_to_id = {}
    if _ADDRLIB_B64:
        blob = _b64.b64decode(_ADDRLIB_B64)
        for i in range(0, len(blob), 8):
            rva, rid = struct.unpack_from('<II', blob, i)
            rva_to_id[rva] = rid
    else:
        version_key = 's' if VERSION == 'se' else 'a'
        id_key = 'si' if VERSION == 'se' else 'ai'
        for s in SYMBOLS:
            rva = s.get(version_key)
            rid = s.get(id_key)
            if rva and rid:
                rva_to_id[rva] = rid
        if FALLBACK_SYMBOLS:
            for s in FALLBACK_SYMBOLS:
                rva = s.get(version_key)
                rid = s.get(id_key)
                if rva and rid and rva not in rva_to_id:
                    rva_to_id[rva] = rid
    return rva_to_id


def _format_id_comment(rva, rva_to_id):
    rid = rva_to_id.get(rva)
    if rid is None:
        return None
    return 'REL::ID(' + str(rid) + ')'


def _import_vtable_names():
    monitor.setMessage('Naming virtual functions from vtable addresses...')
    fm = currentProgram.getFunctionManager()
    sym_table = currentProgram.getSymbolTable()
    memory = currentProgram.getMemory()
    ptr_size = currentProgram.getDefaultPointerSize()
    base_addr = currentProgram.getImageBase()
    rva_to_id = _build_rva_to_id()
    named_vfuncs = 0
    vtbl_not_found = 0
    vtbl_found = 0
    read_fail = 0
    no_func = 0
    already_named = 0
    id_comments_added = 0
    for vt in VTABLES:
        vname, class_full_name, vtbl_size, category, slots = vt
        class_short = class_full_name.split('::')[-1]
        vtbl_label = 'VTABLE_' + class_short
        vtbl_syms = list(sym_table.getSymbols(vtbl_label))
        if not vtbl_syms:
            vtbl_not_found += 1
            continue
        vtbl_found += 1
        vtbl_addr = vtbl_syms[0].getAddress()
        for slot_off, slot_name, slot_ret, slot_params in slots:
            if slot_name.startswith('fn_'):
                continue
            try:
                ptr_addr = vtbl_addr.add(slot_off)
                if ptr_size == 8:
                    raw = memory.getLong(ptr_addr)
                    if raw < 0:
                        raw = raw + (1 << 64)
                else:
                    raw = memory.getInt(ptr_addr) & 0xFFFFFFFF
                func_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(raw)
                func = fm.getFunctionAt(func_addr)
                if not func:
                    DisassembleCommand(func_addr, None, True).applyTo(currentProgram)
                    func = fm.getFunctionAt(func_addr)
                if not func:
                    no_func += 1
                    continue
                curr = func.getName()
                was_named = not (curr.startswith('FUN_') or curr.startswith('sub_'))
                func_rva = func_addr.getOffset() - base_addr.getOffset()
                if was_named:
                    already_named += 1
                    cu = currentProgram.getListing().getCodeUnitAt(func_addr)
                    if cu:
                        existing = cu.getComment(0) or ''
                        if 'REL::ID' not in existing and 'RELOCATION_ID' not in existing:
                            id_str = _format_id_comment(func_rva, rva_to_id)
                            if id_str:
                                new_comment = id_str + '\\n' + existing if existing else id_str
                                cu.setComment(0, new_comment)
                                id_comments_added += 1
                else:
                    comment_parts = []
                    id_str = _format_id_comment(func_rva, rva_to_id)
                    if id_str:
                        comment_parts.append(id_str)
                        id_comments_added += 1
                    comment_parts.append('VTABLE ' + class_full_name + '::' + slot_name)
                    comment_parts.append('Slot offset: +0x{:X}'.format(slot_off))
                    comment_parts.append('Source: ' + PROJECT_NAME + ' vtable walk')
                    func.setName(class_short + '::' + slot_name, SourceType.USER_DEFINED)
                    cu = currentProgram.getListing().getCodeUnitAt(func_addr)
                    if cu:
                        cu.setComment(0, '\\n'.join(comment_parts))
                    named_vfuncs += 1
                if slot_ret is not None and slot_params is not None:
                    has_sig = func.getSignature().getReturnType().getClass().getSimpleName() != 'DefaultDataType'
                    if not has_sig:
                        try:
                            fdef = FunctionDefinitionDataType(CategoryPath('/'), slot_name, dtm)
                            ret_dt = resolve_type(slot_ret)
                            if ret_dt:
                                fdef.setReturnType(ret_dt)
                            pdefs = []
                            this_dt = created.get(class_short)
                            this_ptr = dtm.getPointer(this_dt, 8) if this_dt else _PTR
                            pdefs.append(ParameterDefinitionImpl('this', this_ptr, ''))
                            for pname, ptype in slot_params:
                                pdt = resolve_type(ptype) or _PTR
                                pdefs.append(ParameterDefinitionImpl(pname, pdt, ''))
                            fdef.setArguments(pdefs)
                            ApplyFunctionSignatureCmd(func_addr, fdef,
                                SourceType.USER_DEFINED, True, False).applyTo(currentProgram)
                        except Exception:
                            pass
            except Exception:
                read_fail += 1
    print('Named {} virtual functions from vtable addresses'.format(named_vfuncs))
    print('  vtbl_found={} vtbl_not_found={} read_fail={} no_func={} already_named={} id_comments={}'.format(
        vtbl_found, vtbl_not_found, read_fail, no_func, already_named, id_comments_added))

    # Second pass: walk VTABLE_ labels without struct definitions
    handled_labels = set()
    for vt in VTABLES:
        class_short = vt[1].split('::')[-1]
        handled_labels.add('VTABLE_' + class_short)
    text_block = memory.getBlock('.text')
    unnamed_named = 0
    unnamed_walked = 0
    if text_block:
        text_start = text_block.getStart().getOffset()
        text_end = text_start + text_block.getSize()
        # match "FOO" or "FOO_N" where N is the secondary vtable index (2..)
        sec_re = re.compile(r'^(.+?)_(\\d+)$')
        for sym in sym_table.getAllSymbols(False):
            sname = sym.getName()
            if not sname.startswith('VTABLE_') or sname in handled_labels:
                continue
            label_short = sname[7:]
            sec_match = sec_re.match(label_short)
            if sec_match:
                class_short = sec_match.group(1)
                sec_suffix  = '_v' + sec_match.group(2)
            else:
                class_short = label_short
                sec_suffix  = ''
            vtbl_addr = sym.getAddress()
            unnamed_walked += 1
            slot_idx = 0
            while True:
                slot_idx += 1
                try:
                    ptr_addr = vtbl_addr.add((slot_idx - 1) * ptr_size)
                    if ptr_size == 8:
                        raw = memory.getLong(ptr_addr)
                        if raw < 0:
                            raw = raw + (1 << 64)
                    else:
                        raw = memory.getInt(ptr_addr) & 0xFFFFFFFF
                    if raw < text_start or raw >= text_end:
                        break
                    func_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(raw)
                    func = fm.getFunctionAt(func_addr)
                    if not func:
                        DisassembleCommand(func_addr, None, True).applyTo(currentProgram)
                        func = fm.getFunctionAt(func_addr)
                    if not func:
                        break
                    curr = func.getName()
                    if not (curr.startswith('FUN_') or curr.startswith('sub_')):
                        continue
                    func_name = 'Func{}{}'.format(slot_idx, sec_suffix)
                    func.setName(class_short + '::' + func_name, SourceType.USER_DEFINED)
                    func_rva = func_addr.getOffset() - base_addr.getOffset()
                    cu = currentProgram.getListing().getCodeUnitAt(func_addr)
                    if cu:
                        comment_parts = []
                        id_str = _format_id_comment(func_rva, rva_to_id)
                        if id_str:
                            comment_parts.append(id_str)
                        comment_parts.append('VTABLE ' + class_short + '::' + func_name)
                        comment_parts.append('Slot offset: +0x{:X}'.format((slot_idx - 1) * ptr_size))
                        comment_parts.append('Source: ' + PROJECT_NAME + ' vtable walk (unnamed)')
                        cu.setComment(0, '\\n'.join(comment_parts))
                    unnamed_named += 1
                except Exception:
                    break
    print('Unnamed vtable walk: {} vtables walked, {} functions named'.format(
        unnamed_walked, unnamed_named))


def _import_fallback_symbols():
    """Apply fallback symbols only to addresses not yet named."""
    version_key = 's' if VERSION == 'se' else 'a'
    base_addr = currentProgram.getImageBase()
    fm = currentProgram.getFunctionManager()
    symbol_table = currentProgram.getSymbolTable()

    print('Applying ' + str(len(FALLBACK_SYMBOLS)) + ' fallback symbols...')
    count_applied = count_skipped = 0

    for s in FALLBACK_SYMBOLS:
        off = s.get(version_key)
        if not off:
            continue
        addr = base_addr.add(int(off))
        sname = s['n']

        try:
            f = fm.getFunctionAt(addr)
            if not f:
                DisassembleCommand(addr, None, True).applyTo(currentProgram)
                f = fm.getFunctionAt(addr)

            if f:
                curr = f.getName()
                if not (curr.startswith('FUN_') or curr.startswith('sub_')):
                    count_skipped += 1
                    continue
                f.setName(sname, SourceType.USER_DEFINED)
            else:
                symbol_table.createLabel(addr, sname, SourceType.USER_DEFINED)

            comment_parts = []
            se_id = s.get('si')
            ae_id = s.get('ai')
            if se_id and ae_id:
                comment_parts.append('RELOCATION_ID(' + str(se_id) + ', ' + str(ae_id) + ')')
            elif se_id:
                comment_parts.append('REL::ID(' + str(se_id) + ')')
            elif ae_id:
                comment_parts.append('REL::ID(' + str(ae_id) + ')')
            src = s.get('src', '')
            if src == 'skyrimae.rename':
                comment_parts.append('Source: AE rename database (fallback)')
            elif src:
                comment_parts.append('Source: ' + src + ' (fallback)')
            if comment_parts:
                cu = currentProgram.getListing().getCodeUnitAt(addr)
                if cu:
                    cu.setComment(0, '\\n'.join(comment_parts))
            count_applied += 1
        except:
            pass

    print('Fallback: applied ' + str(count_applied) + ', skipped (already named): ' + str(count_skipped))


run()
'''


# ---------------------------------------------------------------------------
# Script generation
# ---------------------------------------------------------------------------

def generate_script(
    enums: dict,
    structs: dict,
    vtable_structs: dict,
    output_path: str,
    version: str,
    symbols_json: str,
    fallback_symbols_json: str = '[]',
    template_source: str = '',
    project_name: str = 'CommonLibSSE',
    script_header: Optional[str] = None,
    script_footer: Optional[str] = None,
    address_lib_map: Optional[Dict[int, int]] = None,
) -> Tuple[int, int]:
    """Generate a self-contained Ghidra import script.

    Parameters
    ----------
    enums, structs, vtable_structs:
        Type data dicts produced by the clang_types + build_vtable_structs pipeline.
    output_path:
        File path for the generated .py script.
    version:
        Version key embedded in script (e.g. 'se', 'ae').
    symbols_json, fallback_symbols_json:
        JSON-encoded symbol arrays.
    template_source:
        Python source for TEMPLATE_TYPE_MAP.
    project_name:
        Human-readable project name for comment strings (default 'CommonLibSSE').
    script_header, script_footer:
        Override the default Ghidra Jython header/footer.
    address_lib_map:
        Optional dict of {rva: id} from the address library. Encoded as a
        base64 binary blob for reverse RVA→ID lookups at import time.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    header = script_header if script_header is not None else GHIDRA_SCRIPT_HEADER
    footer = script_footer if script_footer is not None else GHIDRA_SCRIPT_FOOTER

    lines = [header]

    lines.append('VERSION = {}'.format(repr(version)))
    lines.append('PROJECT_NAME = {}'.format(repr(project_name)))
    lines.append('')

    # VTABLES
    lines.append('VTABLES = [')
    for vt in sorted(vtable_structs.values(), key=lambda v: v['name']):
        lines.append('    ({}, {}, {}, {}, {}),'.format(
            repr(vt['name']), repr(vt['class_full_name']), repr(vt['size']),
            repr(vt['category']), repr(vt['slots'])))
    lines.append(']')
    lines.append('')

    # ENUMS — convert unsigned values >= 2^63 to signed for Java long
    def _wrap_signed(values):
        out = []
        for n, v in values:
            if v >= (1 << 63):
                v -= (1 << 64)
            out.append((n, v))
        return out

    lines.append('ENUMS = [')
    for en in sorted(enums.values(), key=lambda e: e['full_name']):
        name = en['name']
        size = en['size']
        category = en['category']
        values = _wrap_signed(en['values'])
        val_str = repr(values)
        lines.append('    ({}, {}, {}, {}),'.format(
            repr(name), repr(size), repr(category), val_str))
    lines.append(']')
    lines.append('')

    # STRUCTS
    lines.append('STRUCTS = [')
    for st in sorted(structs.values(), key=lambda s: s['full_name']):
        name = st['name']
        size = st['size']
        category = st['category']
        has_vtable = st['has_vtable']
        bases = st['bases']

        fields = sorted(st['fields'], key=lambda f: f['offset'])
        seen_names = {}
        deduped_fields = []
        for f in fields:
            n = f['name']
            if n in seen_names:
                seen_names[n] += 1
                n = '{}_{}'.format(n, seen_names[n])
            else:
                seen_names[n] = 0
            deduped_fields.append((n, f['type'], f['offset'], f['size']))

        lines.append('    ({}, {}, {}, {}, {}, {}),'.format(
            repr(name), repr(size), repr(category),
            repr(deduped_fields), repr(bases), repr(has_vtable)))
    lines.append(']')
    lines.append('')

    # Build class::method -> structured signature lookup from method data
    _method_sd_lookup = {}
    for st in structs.values():
        class_short = st['name']
        for mname, (ret, params) in st.get('method_sigs', {}).items():
            if ret and params is not None:
                _method_sd_lookup[class_short + '::' + mname] = [ret, params, 0]

    # Inject structured signatures into symbol entries
    _syms = json.loads(symbols_json)
    _sig_count = 0
    for s in _syms:
        if s['t'] == 'func' and not s.get('sd') and not s.get('sig') and '::' in s.get('n', ''):
            sd = _method_sd_lookup.get(s['n'])
            if sd:
                s['sd'] = sd
                _sig_count += 1
    if _sig_count:
        symbols_json = json.dumps(_syms, separators=(',', ':'))

    lines.append('SYMBOLS = ' + symbols_json)
    lines.append('')

    # Upgrade fallback symbols that match vtable slots
    _vtable_sigs = {}
    for vt in vtable_structs.values():
        class_short = vt['class_full_name'].split('::')[-1]
        for _off, slot_name, slot_ret, slot_params in vt['slots']:
            if not slot_name.startswith('fn_') and not slot_name.startswith('__'):
                _vtable_sigs[class_short + '::' + slot_name] = (slot_ret, slot_params)
    if fallback_symbols_json != '[]' and _vtable_sigs:
        _fb = json.loads(fallback_symbols_json)
        _upgraded = 0
        for s in _fb:
            sig_info = _vtable_sigs.get(s.get('n'))
            if sig_info:
                s['src'] = project_name
                _upgraded += 1
        if _upgraded:
            print('  Upgraded {} vtable-known fallback symbols to {} source'.format(_upgraded, project_name))
            fallback_symbols_json = json.dumps(_fb, separators=(',', ':'))

    lines.append('FALLBACK_SYMBOLS = ' + fallback_symbols_json)
    lines.append('')

    # Address library RVA→ID reverse map (base64 binary blob)
    if address_lib_map:
        import base64 as _b64
        pairs = sorted(address_lib_map.items())
        blob = b''.join(struct.pack('<II', rva, rid) for rva, rid in pairs)
        b64 = _b64.b64encode(blob).decode('ascii')
        lines.append('_ADDRLIB_B64 = (')
        for i in range(0, len(b64), 120):
            lines.append("    '" + b64[i:i+120] + "'")
        lines.append(')')
    else:
        lines.append("_ADDRLIB_B64 = ''")
    lines.append('')

    # Template type map
    if template_source:
        lines.append(template_source)
    else:
        lines.append('TEMPLATE_TYPE_MAP = {}')
    lines.append('')

    lines.append(footer)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    return len(enums), len(structs)
