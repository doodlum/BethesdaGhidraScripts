#!/usr/bin/env python3
"""Generic RTTI-driven vtable naming pipeline.

Works on any MSVC x64 PE binary that's already been imported into a
Ghidra project.  Three phases:

  1. RTTI scan: walk the binary's memory blocks for CompleteObjectLocator
     structs (sig==1 + pSelf self-reference), demangle each
     TypeDescriptor, and emit (vtable_va, class_name) pairs for every
     class in the binary.
  2. Slot expansion: walk each vtable's 8-byte function pointer slots
     and emit (target_va, Class::Func<N>) labels.  Termination on zero,
     non-.text pointer, or hitting the next known vtable.
  3. Apply: for each (target_va, name), create a function at that
     address (if Ghidra doesn't already have one) and rename if the
     current name is FUN_*/thunk_*/sub_*.

Usage:
  python run_vtable_pipeline.py <project_dir> <project_name> <program_path> [--dry-run]

Example:
  python run_vtable_pipeline.py C:/GhidraProjects Combined /Fallout4/Fallout4VR_1_2_72.exe

This is the same pipeline that took SF 1.16.236 from 4,202 named
functions (2.3%) to 64,452 (30.5%).  Pure RTTI — no CommonLib headers
required, so works for any binary.
"""
from __future__ import annotations

import csv
import os
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = REPO_DIR / "tools" / "ghidra"

DEFAULT_MAX_SLOTS = 1000

_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_<>$~?@-]")


def sanitize_component(part):
    part = part.strip()
    if not part:
        return "_"
    cleaned = _SAFE_COMPONENT_RE.sub("_", part)
    if cleaned and cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned or "_"


def split_namespaced(full):
    return [sanitize_component(p) for p in full.split("::")]


def demangle_class(mangled):
    """Minimal MSVC class TypeDescriptor demangler."""
    if mangled.startswith((".?AV", ".?AU", ".?AW")):
        rest = mangled[4:]
    else:
        return mangled
    if rest.endswith("@@"):
        rest = rest[:-2]
    parts = [p for p in rest.split("@") if p]
    if not parts:
        return "UnknownClass"
    if any("?$" in p for p in parts):
        return rest.replace("@", "::").replace("?$", "T_").replace("?", "_")
    return "::".join(reversed(parts))


# ---------------------------------------------------------------------------
#  Phase 1+2: RTTI scan + vtable slot expansion (operate on Ghidra memory)
# ---------------------------------------------------------------------------

def scan_rtti_vtables(program):
    """Return {vtable_va: class_name} for every RTTI-discovered vtable.

    Reads bytes directly from the Ghidra Program memory; works for any
    MSVC PE binary (x86 or x64) imported into Ghidra.

    Architecture-dependent COL layout (MSVC RTTI):
        x64 (sig==1, 6 DWORDs/24B): off, cd, pTD-RVA, pCHD-RVA, pSelf-RVA
        x86 (sig==0, 5 DWORDs/20B): off, cd, pTD-abs, pCHD-abs (no pSelf)
    Vtable slot pointer is uint64 (x64) or uint32 (x86), stored as
    absolute VA in both cases.
    """
    import jpype
    memory = program.getMemory()
    af = program.getAddressFactory()
    ds = af.getDefaultAddressSpace()
    image_base = program.getImageBase().getOffset()
    ptr_size = program.getDefaultPointerSize()  # 4 (x86) or 8 (x64)
    is_x64 = (ptr_size == 8)
    col_struct_size = 24 if is_x64 else 20
    expected_sig = 1 if is_x64 else 0
    print(f"  Arch: {'x64' if is_x64 else 'x86'} (ptr_size={ptr_size})")

    # Build section list and pick scannable (read-only, initialized, non-exec)
    # candidate blocks.  Some unpacked binaries split a PE section into
    # multiple Ghidra blocks (init + uninit tail), so we treat each
    # initialized block independently.
    scan_blocks = []
    sects = []
    for block in memory.getBlocks():
        start = block.getStart().getOffset()
        end   = block.getEnd().getOffset()
        size  = end - start + 1
        sect = {"name": block.getName(),
                "vaddr": start - image_base,
                "vsize": size,
                "start_va": start, "end_va": end,
                "block": block}
        sects.append(sect)
        if (block.isInitialized() and block.isRead() and not block.isExecute()
                and size > 0x1000):
            scan_blocks.append(sect)
    if not scan_blocks:
        return {}

    ByteArray = jpype.JArray(jpype.JByte)
    CHUNK = 64 * 1024
    block_bytes = {}
    for sect in scan_blocks:
        buf_all = bytearray(sect["vsize"])
        n_unread = 0
        for off in range(0, sect["vsize"], CHUNK):
            n = min(CHUNK, sect["vsize"] - off)
            buf = ByteArray(n)
            try:
                memory.getBytes(ds.getAddress(sect["start_va"] + off), buf, 0, n)
                for i in range(n):
                    buf_all[off + i] = buf[i] & 0xff
            except Exception:
                n_unread += n
        if 0 < n_unread < sect["vsize"]:
            print(f"  NOTE: {n_unread:,} bytes of {sect['name']} unreadable; zeros")
        block_bytes[id(sect)] = bytes(buf_all)

    image_rva_max = max(s["vaddr"] + s["vsize"] for s in sects)

    def read_any_rva(rva, n):
        for s in scan_blocks:
            if s["vaddr"] <= rva < s["vaddr"] + s["vsize"]:
                local = rva - s["vaddr"]
                buf = block_bytes[id(s)]
                if local + n <= len(buf):
                    return buf[local:local + n]
        # Fallback: ghidra memory for non-cached blocks (e.g., .data sect)
        target_va = image_base + rva
        for s in sects:
            if s["vaddr"] <= rva < s["vaddr"] + s["vsize"]:
                tmp = ByteArray(n)
                try:
                    memory.getBytes(ds.getAddress(target_va), tmp, 0, n)
                    return bytes((b & 0xff) for b in tmp)
                except Exception:
                    return None
        return None

    # Pass 1: COL discovery.
    #   x64 — sig==1, pSelf self-reference (strong), pTD/pCHD are RVAs.
    #   x86 — sig==0, no pSelf; validate by pTD/pCHD pointing into image
    #         (absolute VAs, converted to RVAs here for uniformity).
    cols = {}
    for sect in scan_blocks:
        bytes_buf = block_bytes[id(sect)]
        sect_rva = sect["vaddr"]
        for p in range(0, len(bytes_buf) - col_struct_size, 4):
            sig = struct.unpack_from("<I", bytes_buf, p)[0]
            if sig != expected_sig:
                continue
            if is_x64:
                off, cd, ptd, pcd, pself = struct.unpack_from(
                    "<IIIII", bytes_buf, p + 4)
                col_rva = sect_rva + p
                if pself != col_rva:
                    continue
                if ptd >= image_rva_max or pcd >= image_rva_max:
                    continue
                cols[col_rva] = ptd
            else:
                off, cd, ptd_abs, pcd_abs = struct.unpack_from(
                    "<IIII", bytes_buf, p + 4)
                # x86 stores absolute VAs; convert to RVA.
                if ptd_abs < image_base or pcd_abs < image_base:
                    continue
                ptd = ptd_abs - image_base
                pcd = pcd_abs - image_base
                if ptd >= image_rva_max or pcd >= image_rva_max:
                    continue
                col_rva = sect_rva + p
                cols[col_rva] = ptd
    print(f"  Pass1 COL candidates (sig-anchored): {len(cols):,}")

    # Pass 2: demangle TypeDescriptor names (MSVC layout varies — name
    # starts at +0x08 for some builds, +0x10 for others; scan for ".?A").
    name_by_col = {}
    for col_rva, ptd in cols.items():
        head = read_any_rva(ptd, 0x20)
        if head is None:
            continue
        prefix_pos = None
        for off2 in (0x08, 0x10):
            if head[off2:off2 + 3] == b".?A":
                prefix_pos = off2
                break
        if prefix_pos is None:
            continue
        name_buf = read_any_rva(ptd + prefix_pos, 256)
        if name_buf is None:
            continue
        end = name_buf.find(b"\x00")
        if end == -1:
            continue
        mangled = name_buf[:end].decode("latin-1", errors="replace")
        if not mangled.startswith(".?A"):
            continue
        name_by_col[col_rva] = demangle_class(mangled)
    print(f"  Pass2 typed COLs (demangled):        {len(name_by_col):,}")

    # x86 fallback: many older MSVC x86 binaries store COL fields with a
    # non-zero signature or omit it entirely.  Anchor on TypeDescriptor
    # name strings instead, then locate COLs by finding DWORDs that
    # reference each TypeDescriptor and validating the surrounding bytes.
    if not is_x64 and len(name_by_col) < 200:
        added = 0
        # Step A: find every '.?A...' string in scanned blocks.
        td_va_to_name = {}
        for sect in scan_blocks:
            bytes_buf = block_bytes[id(sect)]
            sect_va = sect["start_va"]
            i = 0
            while True:
                i = bytes_buf.find(b".?A", i)
                if i < 0:
                    break
                end = bytes_buf.find(b"\x00", i)
                if end < 0 or end - i > 1024:
                    i += 1
                    continue
                mangled = bytes_buf[i:end].decode("latin-1", errors="replace")
                if not mangled.startswith((".?AV", ".?AU", ".?AW")):
                    i = end + 1
                    continue
                # x86 TD: pVFTable(4) spare(4) name(...) — name at +8.
                td_va = sect_va + i - 8
                if td_va >= image_base:
                    td_va_to_name[td_va] = demangle_class(mangled)
                i = end + 1
        # Step B: scan for DWORDs == td_va, then look back at offsets
        # -12 (5-DWORD COL with sig) and -8 (legacy 4-DWORD COL) for the
        # COL start.  Accept if pCHD points into the image.
        for sect in scan_blocks:
            bytes_buf = block_bytes[id(sect)]
            sect_va = sect["start_va"]
            sect_rva = sect["vaddr"]
            n = len(bytes_buf)
            for p in range(16, n - 4, 4):
                td_abs = struct.unpack_from("<I", bytes_buf, p)[0]
                if td_abs not in td_va_to_name:
                    continue
                # Try 5-DWORD layout first (offset -12 = COL start).
                for back, has_sig in ((12, True), (8, False)):
                    col_p = p - back
                    if col_p < 0:
                        continue
                    if has_sig:
                        sig_val = struct.unpack_from("<I", bytes_buf, col_p)[0]
                        if sig_val not in (0, 1):
                            continue
                    pcd_off = col_p + (16 if has_sig else 12)
                    if pcd_off + 4 > n:
                        continue
                    pcd_abs = struct.unpack_from("<I", bytes_buf, pcd_off)[0]
                    if pcd_abs < image_base:
                        continue
                    if (pcd_abs - image_base) >= image_rva_max:
                        continue
                    col_rva = sect_rva + col_p
                    if col_rva not in name_by_col:
                        name_by_col[col_rva] = td_va_to_name[td_abs]
                        added += 1
                    break
        print(f"  x86 fallback (TD-anchored) added:    {added:,}")
        print(f"  Total typed COLs after fallback:     {len(name_by_col):,}")

    # Pass 3: scan for a slot whose stored pointer == abs VA of a known COL.
    # Vtable layout: [COL-ptr][slot0][slot1]...  COL ptr precedes vtable by
    # one pointer-width slot, in both x86 and x64.
    vtables = {}
    ptr_fmt = "<Q" if is_x64 else "<I"
    for sect in scan_blocks:
        bytes_buf = block_bytes[id(sect)]
        sect_rva = sect["vaddr"]
        for p in range(0, len(bytes_buf) - ptr_size, ptr_size):
            ptr = struct.unpack_from(ptr_fmt, bytes_buf, p)[0]
            if ptr == 0:
                continue
            col_rva = ptr - image_base
            if col_rva not in name_by_col:
                continue
            vt_va = image_base + sect_rva + p + ptr_size
            if vt_va not in vtables:
                vtables[vt_va] = name_by_col[col_rva]
    return vtables


def expand_vtables(program, vtables):
    """For each vtable, walk slots and yield (target_va, Class::Func<N>).

    Termination per vtable:
      * zero pointer
      * pointer outside .text
      * next slot is another known vtable VA
      * DEFAULT_MAX_SLOTS hard cap
    """
    memory = program.getMemory()
    af = program.getAddressFactory()
    ds = af.getDefaultAddressSpace()
    ptr_size = program.getDefaultPointerSize()
    ptr_mask = (1 << (ptr_size * 8)) - 1

    text_start = text_end = None
    for block in memory.getBlocks():
        if block.getName() == ".text" or block.isExecute():
            if text_start is None or block.getStart().getOffset() < text_start:
                text_start = block.getStart().getOffset()
            if text_end is None or block.getEnd().getOffset() > text_end:
                text_end = block.getEnd().getOffset()

    def read_ptr(va):
        if ptr_size == 8:
            return memory.getLong(ds.getAddress(va)) & ptr_mask
        return memory.getInt(ds.getAddress(va)) & ptr_mask

    vtable_va_set = set(vtables.keys())
    for vt_va, cls in vtables.items():
        for slot_idx in range(DEFAULT_MAX_SLOTS):
            slot_va = vt_va + slot_idx * ptr_size
            try:
                ptr_val = read_ptr(slot_va)
            except Exception:
                break
            if ptr_val == 0:
                break
            if not (text_start <= ptr_val < text_end):
                break
            next_va = vt_va + (slot_idx + 1) * ptr_size
            if slot_idx > 0 and next_va in vtable_va_set:
                yield (ptr_val, f"{cls}::Func{slot_idx}")
                break
            yield (ptr_val, f"{cls}::Func{slot_idx}")


# ---------------------------------------------------------------------------
#  Phase 3: apply names + create functions where needed
# ---------------------------------------------------------------------------

# Ghidra's own placeholders.  We deliberately do NOT match IDA-style
# prefixes (sub_/loc_/Sub_/j_/...) because those may have been intentionally
# applied by a CSV/PDB importer as meaningful names; the only truly safe
# signal is Ghidra's SourceType.DEFAULT bit on the symbol itself.
_GHIDRA_DEFAULT_NAME_RE = re.compile(r"^(?:FUN|thunk_FUN)_[0-9a-fA-F]+$")


def _is_overwritable(func):
    """True iff the function's name is a known Ghidra-default placeholder.

    Conservative on purpose: only renames when we are 100% confident the
    current name carries no meaning.  Symbol source must be DEFAULT
    (Ghidra-generated), AND the name must match a Ghidra placeholder
    regex.  Any IMPORTED / USER_DEFINED / ANALYSIS-source symbol is left
    untouched.
    """
    from ghidra.program.model.symbol import SourceType
    sym = func.getSymbol()
    if sym is None:
        return False
    if sym.getSource() != SourceType.DEFAULT:
        return False
    return bool(_GHIDRA_DEFAULT_NAME_RE.match(func.getName()))


def apply_naming(program, slot_pairs, monitor, dry_run=False):
    """Apply each (target_va, name) to the program; create functions at
    slot-target VAs that don't have one yet.  Returns stats dict.
    """
    from ghidra.program.model.symbol import SourceType
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.app.cmd.disassemble import DisassembleCommand

    fm = program.getFunctionManager()
    sym = program.getSymbolTable()
    listing = program.getListing()
    global_ns = program.getGlobalNamespace()
    af = program.getAddressFactory()
    ds = af.getDefaultAddressSpace()
    memory = program.getMemory()

    text_start = text_end = None
    for block in memory.getBlocks():
        if block.getName() == ".text" or block.isExecute():
            if text_start is None or block.getStart().getOffset() < text_start:
                text_start = block.getStart().getOffset()
            if text_end is None or block.getEnd().getOffset() > text_end:
                text_end = block.getEnd().getOffset()

    ns_cache = {}
    def get_or_create_namespace(path_parts):
        if not path_parts:
            return global_ns
        key = "::".join(path_parts)
        if key in ns_cache:
            return ns_cache[key]
        parent = global_ns
        for part in path_parts:
            sub = sym.getNamespace(part, parent)
            if sub is None:
                if not dry_run:
                    sub = sym.createNameSpace(parent, part, SourceType.USER_DEFINED)
                else:
                    sub = parent  # dry-run: don't create
            parent = sub
        ns_cache[key] = parent
        return parent

    stats = {"unique_vas": 0, "renamed": 0, "already_named": 0,
             "created": 0, "create_fail": 0, "outside_text": 0,
             "errors": 0}
    already_named_samples = []  # first ~10 names we skipped
    seen = set()
    txid = program.startTransaction("RTTI vtable pipeline") if not dry_run else None
    try:
        for target_va, name in slot_pairs:
            if target_va in seen:
                continue
            seen.add(target_va)
            stats["unique_vas"] += 1
            if target_va < text_start or target_va >= text_end:
                stats["outside_text"] += 1
                continue
            addr = ds.getAddress(target_va)
            func = fm.getFunctionAt(addr)
            if func is None:
                inside = fm.getFunctionContaining(addr)
                if inside is not None:
                    stats["create_fail"] += 1
                    continue
                if dry_run:
                    stats["create_fail"] += 1  # would attempt to create
                    continue
                if listing.getInstructionAt(addr) is None:
                    DisassembleCommand(addr, None, True).applyTo(program, monitor)
                if not CreateFunctionCmd(addr).applyTo(program, monitor):
                    stats["create_fail"] += 1
                    continue
                func = fm.getFunctionAt(addr)
                if func is None:
                    stats["create_fail"] += 1
                    continue
                stats["created"] += 1
            if not _is_overwritable(func):
                stats["already_named"] += 1
                if len(already_named_samples) < 10:
                    already_named_samples.append(
                        (f"0x{target_va:x}", func.getName()))
                continue
            parts = split_namespaced(name)
            leaf = parts[-1]
            ns_path = parts[:-1]
            if dry_run:
                stats["renamed"] += 1
                continue
            try:
                target_ns = get_or_create_namespace(ns_path)
                func.setParentNamespace(target_ns)
                func.setName(leaf, SourceType.USER_DEFINED)
                stats["renamed"] += 1
            except Exception as e:
                stats["errors"] += 1
                if stats["errors"] < 5:
                    print(f"  err 0x{target_va:x} '{name[:60]}': {e}")
    finally:
        if txid is not None:
            program.endTransaction(txid, True)

    if already_named_samples:
        print("  sample of preserved (already-named) targets:")
        for va, nm in already_named_samples:
            print(f"    {va}  {nm[:80]}")
    return stats


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    project_dir, project_name, program_path = sys.argv[1:4]
    dry_run = "--dry-run" in sys.argv

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    print(f"Project:  {project_dir}/{project_name}")
    print(f"Program:  {program_path}")
    print(f"Dry run:  {dry_run}")

    with pyghidra.open_project(project_dir, project_name, create=False) as project:
        df = project.getProjectData().getFile(program_path)
        if df is None:
            print(f"ERROR: program not found: {program_path}")
            sys.exit(2)
        consumer = java.lang.Object()
        program = df.getDomainObject(consumer, not dry_run, False, monitor)
        try:
            print(f"\n=== Phase 1+2: RTTI scan ===")
            vtables = scan_rtti_vtables(program)
            n_vt = len(vtables)
            print(f"  Discovered {n_vt:,} vtables via RTTI")
            if n_vt == 0:
                print("  No vtables found — aborting")
                return

            # Stats before
            fm = program.getFunctionManager()
            n_before_total = fm.getFunctionCount()
            n_before_named = sum(
                1 for f in fm.getFunctions(True)
                if not f.getName().startswith(("FUN_", "thunk_FUN_", "sub_")))

            print(f"\n=== Phase 3: slot expansion + apply ===")
            print(f"  before: {n_before_named:,} / {n_before_total:,} named "
                  f"({100*n_before_named/max(n_before_total,1):.1f}%)")

            stats = apply_naming(program, expand_vtables(program, vtables),
                                  monitor, dry_run=dry_run)

            # Save
            if not dry_run:
                print(f"\nSaving program ...")
                program.save("RTTI vtable pipeline", monitor)

            # Stats after
            n_after_total = fm.getFunctionCount()
            n_after_named = sum(
                1 for f in fm.getFunctions(True)
                if not f.getName().startswith(("FUN_", "thunk_FUN_", "sub_")))

            print(f"\n=== Summary ===")
            print(f"  vtables discovered:    {n_vt:,}")
            print(f"  unique target VAs:     {stats['unique_vas']:,}")
            print(f"  functions created:     {stats['created']:,}")
            print(f"  functions renamed:     {stats['renamed']:,}")
            print(f"  already named:         {stats['already_named']:,}")
            print(f"  create fail:           {stats['create_fail']:,}")
            print(f"  outside .text:         {stats['outside_text']:,}")
            print(f"  errors:                {stats['errors']:,}")
            print()
            print(f"  named before:  {n_before_named:>7,} / {n_before_total:>7,} "
                  f"({100*n_before_named/max(n_before_total,1):.1f}%)")
            print(f"  named after:   {n_after_named:>7,} / {n_after_total:>7,} "
                  f"({100*n_after_named/max(n_after_total,1):.1f}%)")
            print(f"  delta:         {n_after_named - n_before_named:+,} named, "
                  f"{n_after_total - n_before_total:+,} total funcs")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
