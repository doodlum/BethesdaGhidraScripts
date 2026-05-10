"""Regex-based relocation/symbol scanner for libxse/commonlibf4.

ID format (IDs.h) -- single AE ID per entry:
  namespace RE::ID {
    namespace Actor {
      inline constexpr REL::ID AddPerk{ 2230121 };
    }
  }

Header usage:
  static REL::Relocation<func_t> func{ ID::Actor::AddPerk };

RTTI/NiRTTI (IDs_RTTI.h / IDs_NiRTTI.h):
  inline constexpr REL::ID Actor{ 4839606 };

VTABLE (IDs_VTABLE.h):
  inline constexpr std::array<REL::ID, 17> Actor{ REL::ID(1455516), ... };

Public API:
  collect_relocations(re_include, addr_lib, verbose) ->
      (func_syms, label_syms, static_methods)
  Each sym has 'ae_off' (AE offset, or None if unresolved).
"""
from __future__ import annotations

import glob
import os
import re
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# IDs.h: inline constexpr REL::ID Name{ id1[, id2[, id3]] };
_ID_DECL_RE = re.compile(
    r'inline\s+constexpr\s+REL::ID\s+(\w+)\s*\{([^}]+)\}'
)

# IDs_VTABLE.h: std::array<REL::ID, N> Name{ REL::ID(id), ... }
_VTABLE_ARRAY_RE = re.compile(
    r'inline\s+constexpr\s+std::array<REL::ID,\s*(\d+)>\s+(\w+)\s*\{([^}]+)\}'
)
_REL_ID_CALL_RE = re.compile(r'REL::ID\s*\(\s*(\d+)\s*\)')

# Header: REL::Relocation<func_t> func{ ID::Class::Method }
_RELOC_REF_RE = re.compile(
    r'REL::Relocation<[^>]+>\s+\w+\s*\{\s*ID::([\w:]+)\s*\}'
)

# Namespace detection
_NS_OPEN_RE   = re.compile(r'\bnamespace\s+([\w:]+)\s*\{')
_NS_DECL_RE   = re.compile(r'^\s*namespace\s+([\w:]+)\s*$')
_CLASS_RE     = re.compile(r'\b(?:class|struct)\s+(\w+)\s*(?:final\s*)?(?::\s*[^{]*?)?\{')
_CLASS_DECL_RE = re.compile(r'^\s*(?:class|struct)\s+(\w+)\s*(?:final\s*)?(?::\s*[^{;]*)?\s*$')
_METHOD_DEF_RE = re.compile(
    r'(?:\[\[.*?\]\]\s*)*'
    r'(?:static\s+)?(?:virtual\s+)?(?:inline\s+)?'
    r'(?:[\w:*&<>,\s]+?)\s+(\w+)\s*\([^)]*\)\s*'
    r'(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:final\s*)?\s*\{'
)
_METHOD_DECL_RE = re.compile(
    r'(?:\[\[.*?\]\]\s*)*'
    r'(?:static\s+)?(?:virtual\s+)?(?:inline\s+)?'
    r'(?:[\w:*&<>,\s]+?)\s+(\w+)\s*\([^)]*\)\s*'
    r'(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:final\s*)?\s*$'
)
_STATIC_METHOD_RE = re.compile(
    r'static\s+(?!constexpr\s+auto\s+RTTI|constexpr\s+auto\s+VTABLE)'
    r'.*?\b(\w+)\s*\([^)]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?;'
)


# ---------------------------------------------------------------------------
# IDs.h parser
# ---------------------------------------------------------------------------

_NS_DECL_BARE_RE = re.compile(r'^\s*namespace\s+([\w:]+)\s*$')  # no brace on same line


def _parse_ids_file(file_path: str) -> Dict[str, int]:
    """Parse IDs.h → {'ClassName::MethodName': ae_id}

    Single AE ID per entry (libxse fork). 0 means missing.
    Handles K&R-style opening braces on the line following the namespace keyword.
    """
    id_map: Dict[str, int] = {}

    try:
        with open(file_path, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return {}

    # scope_stack: list of (name, brace_depth_when_opened)
    scope_stack: List[Tuple[str, int]] = []
    in_re_id   = False
    re_id_depth = -1
    brace_depth = 0
    # pending: namespace declared on a line without '{', waiting for next '{'
    _pending_re_id  = False  # waiting to open RE::ID namespace
    _pending_sub_ns: Optional[str] = None  # waiting to open a sub-namespace

    for line in content.split('\n'):
        stripped = line.strip()
        if stripped.startswith('//'):
            continue

        opens  = line.count('{')
        closes = line.count('}')

        # Resolve pending namespaces when '{' arrives
        if opens > 0:
            if _pending_re_id:
                in_re_id    = True
                re_id_depth = brace_depth
                _pending_re_id = False
            elif _pending_sub_ns is not None and in_re_id:
                scope_stack.append((_pending_sub_ns, brace_depth))
                _pending_sub_ns = None

        # Detect namespace keywords (brace may or may not be on same line).
        # Entry-point is only the qualified form `<X>::ID` (e.g. RE::ID).
        # An unqualified `namespace ID` may legitimately appear nested inside a
        # sub-namespace and must NOT be treated as a re-entry.
        for ns_m in _NS_OPEN_RE.finditer(line):
            ns_name = ns_m.group(1)
            if ns_name.endswith('::ID') and not in_re_id:
                in_re_id    = True
                re_id_depth = brace_depth
            elif in_re_id:
                scope_stack.append((ns_name, brace_depth))

        # Next-line brace: namespace RE::ID\n{
        if opens == 0:
            m = _NS_DECL_BARE_RE.match(line)
            if m:
                ns_name = m.group(1)
                if ns_name.endswith('::ID') and not in_re_id:
                    _pending_re_id = True
                elif in_re_id:
                    _pending_sub_ns = ns_name

        # Parse ID declarations
        if in_re_id:
            id_m = _ID_DECL_RE.search(line)
            if id_m:
                name    = id_m.group(1)
                raw_ids = id_m.group(2)
                ids: List[int] = []
                for tok in raw_ids.split(','):
                    tok = tok.strip()
                    try:
                        ids.append(int(tok))
                    except ValueError:
                        pass
                if ids and ids[0]:
                    if scope_stack:
                        key = '::'.join(s[0] for s in scope_stack) + '::' + name
                    else:
                        key = name
                    id_map[key] = ids[0]

        brace_depth += opens - closes

        # Pop scopes whose depth has been closed
        while scope_stack and scope_stack[-1][1] >= brace_depth:
            scope_stack.pop()

        if in_re_id and brace_depth <= re_id_depth:
            in_re_id = False
            scope_stack = []

    return id_map


# ---------------------------------------------------------------------------
# Brace-tracking context (same structure as SSE reloc_parser)
# ---------------------------------------------------------------------------

class _ContextTracker:
    def __init__(self):
        self.scope_stack: List[Tuple[str, str, int]] = []  # (kind, name, depth)
        self.brace_depth = 0
        self._pending: Optional[Tuple[str, str]] = None
        self._pending_method: Optional[str] = None
        self.method_name: Optional[str] = None
        self._method_depth: Optional[int] = None

    def feed_line(self, line: str):
        stripped = line.lstrip()
        if stripped.startswith('//') or stripped.startswith('#'):
            return
        opens  = line.count('{')
        closes = line.count('}')
        for m in _NS_OPEN_RE.finditer(line):
            self.scope_stack.append(('ns', m.group(1), self.brace_depth))
        for m in _CLASS_RE.finditer(line):
            self.scope_stack.append(('class', m.group(1), self.brace_depth))
        code_line = re.sub(r'\s*//.*$', '', line)
        if opens == 0 and closes == 0:
            m = _NS_DECL_RE.match(code_line)
            if m:
                self._pending = ('ns', m.group(1))
            else:
                m = _CLASS_DECL_RE.match(code_line)
                if m:
                    self._pending = ('class', m.group(1))
                elif self.class_name:
                    m = _METHOD_DECL_RE.search(code_line)
                    if m and m.group(1) not in ('return','if','else','for','while','switch','do'):
                        self._pending_method = m.group(1)
        if self._pending and opens > 0:
            self.scope_stack.append((self._pending[0], self._pending[1], self.brace_depth))
            self._pending = None
        if self.class_name and opens > 0:
            m = _METHOD_DEF_RE.search(line)
            if m:
                self.method_name = m.group(1)
                self._method_depth = self.brace_depth
                self._pending_method = None
            elif self._pending_method:
                self.method_name = self._pending_method
                self._method_depth = self.brace_depth
                self._pending_method = None
        self.brace_depth += opens - closes
        while self.scope_stack and self.scope_stack[-1][2] >= self.brace_depth:
            self.scope_stack.pop()
        if self._method_depth is not None and self.brace_depth <= self._method_depth:
            self.method_name = None
            self._method_depth = None

    @property
    def class_name(self) -> Optional[str]:
        for kind, name, _ in reversed(self.scope_stack):
            if kind == 'class':
                return name
        return None

    @property
    def full_class(self) -> Optional[str]:
        classes = [name for kind, name, _ in self.scope_stack if kind == 'class']
        if not classes:
            return None
        ns = [name for kind, name, _ in self.scope_stack if kind == 'ns']
        return '::'.join(ns + classes)


# ---------------------------------------------------------------------------
# RTTI / NiRTTI / VTABLE label scanner
# ---------------------------------------------------------------------------

def _scan_label_files(
    re_include: str,
    addr_lib,
) -> List[dict]:
    """Scan IDs_RTTI.h, IDs_NiRTTI.h, IDs_VTABLE.h for label symbols (AE-only)."""
    labels: Dict[str, dict] = {}

    # --- RTTI and NiRTTI (single bare ID per entry) ---
    for fname, prefix in (('IDs_RTTI.h', 'RTTI_'), ('IDs_NiRTTI.h', 'NiRTTI_')):
        fpath = os.path.join(re_include, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, encoding='utf-8', errors='replace') as f:
                content = f.read()
        except OSError:
            continue
        for m in _ID_DECL_RE.finditer(content):
            name    = m.group(1)
            raw_ids = m.group(2)
            ids: List[int] = []
            for tok in raw_ids.split(','):
                tok = tok.strip()
                try:
                    ids.append(int(tok))
                except ValueError:
                    pass
            if not ids:
                continue
            id_val = ids[0]
            ae_off = addr_lib.get_ae(id_val)
            lname = prefix + name
            labels.setdefault(lname, {'name': lname, 'ae_off': ae_off, 'id': id_val})

    # --- VTABLE (std::array<REL::ID, N> using REL::ID() constructor) ---
    vtable_path = os.path.join(re_include, 'IDs_VTABLE.h')
    if os.path.isfile(vtable_path):
        try:
            with open(vtable_path, encoding='utf-8', errors='replace') as f:
                content = f.read()
        except OSError:
            content = ''
        for m in _VTABLE_ARRAY_RE.finditer(content):
            name     = m.group(2)
            id_calls = [int(x) for x in _REL_ID_CALL_RE.findall(m.group(3))]
            for idx, id_ in enumerate(id_calls):
                ae_off = addr_lib.get_ae(id_)
                suffix = '' if idx == 0 else '_{}'.format(idx + 1)
                lname = 'VTABLE_' + name + suffix
                labels.setdefault(lname, {'name': lname, 'ae_off': ae_off, 'id': id_})

    return list(labels.values())


# ---------------------------------------------------------------------------
# Header scanner
# ---------------------------------------------------------------------------

def _scan_header(
    file_path: str,
    id_map: Dict[str, int],
    addr_lib,
    root_namespace: str = 'RE',
) -> Tuple[List[dict], Set[Tuple[str, str]]]:
    """Scan a single header for REL::Relocation{ ID::Class::Method } and static methods."""
    func_syms: List[dict] = []
    static_methods: Set[Tuple[str, str]] = set()

    try:
        with open(file_path, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return func_syms, static_methods

    if 'REL::Relocation' not in content and 'static' not in content:
        return func_syms, static_methods

    lines = content.split('\n')
    _ns_pre = root_namespace + '::'

    # Pass 1: static methods
    ctx = _ContextTracker()
    for line in lines:
        ctx.feed_line(line)
        if ctx.class_name:
            for m in _STATIC_METHOD_RE.finditer(line):
                full_cls = ctx.full_class
                if full_cls and full_cls.startswith(_ns_pre):
                    static_methods.add((full_cls[len(_ns_pre):], m.group(1)))

    # Pass 2: REL::Relocation{ ID::Class::Method }
    ctx2 = _ContextTracker()
    for line in lines:
        ctx2.feed_line(line)

        ref_m = _RELOC_REF_RE.search(line)
        if not ref_m:
            continue

        id_key = ref_m.group(1)  # e.g. 'Actor::AddPerk'
        ng_id = id_map.get(id_key)
        if not ng_id:
            continue

        ae_off = addr_lib.get_ae(ng_id)

        sym_class = ctx2.full_class
        if sym_class and sym_class.startswith(_ns_pre):
            sym_class = sym_class[len(_ns_pre):]

        # Name from context, or derive from the ID key
        sym_name = ctx2.method_name
        if not sym_name:
            parts = id_key.split('::')
            sym_name = parts[-1]
            if not sym_class and len(parts) > 1:
                sym_class = '::'.join(parts[:-1])

        func_syms.append({
            'name': sym_name,
            'class_': sym_class,
            'ret': '', 'params': '',
            'is_static': False,
            'ae_off': ae_off,
            'id': ng_id,
        })

    return func_syms, static_methods


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect_relocations(
    re_include: str,
    addr_lib,
    verbose: bool = False,
    root_namespace: str = 'RE',
) -> Tuple[List[dict], List[dict], Set[Tuple[str, str]]]:
    """Scan RE/ headers for relocation symbols.

    Returns (func_syms, label_syms, static_methods).
    Each sym has 'ae_off' (None if unresolved).
    """
    # 1. Parse centralised ID registry
    ids_h = os.path.join(re_include, 'IDs.h')
    id_map = _parse_ids_file(ids_h)
    if verbose:
        print(f'  IDs.h: {len(id_map)} relocation IDs')

    # 2. RTTI / NiRTTI / VTABLE labels
    label_syms = _scan_label_files(re_include, addr_lib)
    if verbose:
        rtti_n  = sum(1 for l in label_syms if l['name'].startswith('RTTI_'))
        nirtti_n = sum(1 for l in label_syms if l['name'].startswith('NiRTTI_'))
        vtbl_n  = sum(1 for l in label_syms if l['name'].startswith('VTABLE_'))
        print(f'  Labels: {rtti_n} RTTI, {nirtti_n} NiRTTI, {vtbl_n} VTABLE')

    # 3. Scan all RE/ headers
    skip = {'IDs.h', 'IDs_RTTI.h', 'IDs_NiRTTI.h', 'IDs_VTABLE.h', 'RTTI.h'}
    all_func: List[dict] = []
    all_statics: Set[Tuple[str, str]] = set()

    for h_path in sorted(glob.glob(os.path.join(re_include, '**', '*.h'), recursive=True)):
        if os.path.basename(h_path) in skip:
            continue
        funcs, statics = _scan_header(h_path, id_map, addr_lib, root_namespace)
        all_func.extend(funcs)
        all_statics |= statics

    if verbose:
        ae_found = sum(1 for f in all_func if f['ae_off'])
        print(f'  Header scan: {len(all_func)} func symbols '
              f'({ae_found} AE), {len(all_statics)} static methods')

    # Dedup by ae_off
    seen: Set[Optional[int]] = set()
    deduped: List[dict] = []
    for f in all_func:
        key = f.get('ae_off')
        if key is None or key not in seen:
            if key is not None:
                seen.add(key)
            deduped.append(f)

    return deduped, label_syms, all_statics
