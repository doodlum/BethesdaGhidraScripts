#!/usr/bin/env python3
"""Walk every labeled vtable in SF 1.7 (Combined.gpr/Starfield.exe) and emit
(class, slot_index, real_method_name) for each slot whose target function
has a real semantic name (not FUN_/thunk_/sub_).

Output: scripts/commonlibsf/refs/sf17_vtable_slot_names.csv
  columns: class, slot, name

The class list is sourced from CommonLibSF IDs_VTABLE.h, identical to what
we used for SF 1.16.  Same IDs map to RVAs via the SF 1.7 versionlib if
available, but we can also locate vtables directly: search the program's
symbol table for symbols matching the class names from sf116_commonlib_names
(those names are version-independent class names).

Simpler approach: parse IDs_VTABLE.h once, look up each class's vtable VA
in SF 1.7 via the SF 1.7 versionlib (NOT 1.16.236 versionlib).  Then walk
slots in SF 1.7 program memory.
"""
from __future__ import annotations

import csv
import os
import re
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = REPO_DIR / "tools" / "ghidra"

# We rely on the SF 1.7 program in Combined.gpr to walk its vtables
PROJECT_DIR  = "C:/GhidraProjects"
PROJECT_NAME = "Combined"
PROGRAM_PATH = "/Starfield/Starfield.exe"

# We need an SF 1.7 versionlib to map REL::IDs to SF 1.7 RVAs.
SF17_VERSIONLIB = Path(r"C:/Development/MasterModTemplate/Shared/AddressLibraries/Starfield/Plugins/versionlib-1-7-36-0.bin")
SF17_VERSIONLIB_ALT = Path(r"C:/Development/MasterModTemplate/Shared/AddressLibraries/Starfield/Plugins")

IDS_VTABLE_H = Path(r"C:/Development/Cell Offset Generator Starfield/external/CommonLibSF/include/RE/IDs_VTABLE.h")

OUT_CSV = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf17_vtable_slot_names.csv"

DEFAULT_MAX_SLOTS = 1000
IMAGE_BASE = 0x140000000


def parse_ids_vtable_h(path):
    """Return list of (id, class_name)."""
    text = path.read_text(encoding="utf-8")
    text = re.sub(r'//[^\n]*', '', text)
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)

    out = []
    ns_stack = []
    brace_depth = 0
    NS_RE = re.compile(r'namespace\s+([A-Za-z0-9_:]+)\s*\{')
    ARR_RE = re.compile(r'inline\s+constexpr\s+std::array<\s*REL::ID,\s*\d+>\s*(\w+)\s*\{\s*REL::ID\((\d+)\)')

    i = 0
    n = len(text)
    while i < n:
        if text[i] == '{':
            brace_depth += 1
            i += 1
            continue
        if text[i] == '}':
            brace_depth -= 1
            if ns_stack and brace_depth < sum(len(x.split('::')) for x in ns_stack):
                ns_stack.pop()
            i += 1
            continue
        m = NS_RE.match(text, i)
        if m:
            ns_stack.append(m.group(1))
            brace_depth += 1
            i = m.end()
            continue
        m = ARR_RE.match(text, i)
        if m:
            ident = m.group(1)
            rid = int(m.group(2))
            full = "::".join(ns_stack + [ident]) if ns_stack else ident
            if rid != 0:
                out.append((rid, full))
            i = m.end()
            continue
        i += 1
    return out


def find_sf17_versionlib():
    """Locate any SF 1.7-ish versionlib for ID lookup."""
    candidates = [
        SF17_VERSIONLIB,
        REPO_DIR / "addresslibrary" / "starfield" / "versionlib-1-7-23-0.bin",
    ]
    # Glob the SFSE plugins dir
    if SF17_VERSIONLIB_ALT.is_dir():
        for p in sorted(SF17_VERSIONLIB_ALT.glob("versionlib-1-7-*.bin")):
            candidates.append(p)
    for c in candidates:
        if c.is_file():
            return c
    return None


def main():
    # Find an SF 1.7 versionlib
    vlib = find_sf17_versionlib()
    if vlib is None:
        print("ERROR: cannot find SF 1.7 versionlib (.bin).  Looked in:")
        print(f"  {SF17_VERSIONLIB}")
        print(f"  {SF17_VERSIONLIB_ALT}")
        sys.exit(2)
    print(f"Using SF 1.7 versionlib: {vlib}")

    sys.path.insert(0, str(REPO_DIR / "scripts" / "commonlibsf"))
    from address_library import AddressLibrary
    al = AddressLibrary()
    sf17_db = al.load_bin(str(vlib))
    print(f"  loaded {len(sf17_db)} ID -> RVA mappings")

    ids = parse_ids_vtable_h(IDS_VTABLE_H)
    print(f"Parsed {len(ids)} vtable IDs from IDs_VTABLE.h")

    # Map class -> SF 1.7 VA via versionlib
    classes_sf17 = []
    n_no_rva = 0
    for rid, cls in ids:
        rva = sf17_db.get(rid)
        if not rva:
            n_no_rva += 1
            continue
        classes_sf17.append((IMAGE_BASE + rva, cls))
    print(f"  resolved to SF 1.7 VAs: {len(classes_sf17)} (missing: {n_no_rva})")

    # Open SF 1.7 program for memory + symbol reads
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    with pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=False) as project:
        domain_file = project.getProjectData().getFile(PROGRAM_PATH)
        if domain_file is None:
            print(f"ERROR: program not found: {PROGRAM_PATH}")
            sys.exit(2)
        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, False, False, monitor)
        try:
            memory = program.getMemory()
            addr_factory = program.getAddressFactory()
            default_space = addr_factory.getDefaultAddressSpace()
            fm = program.getFunctionManager()

            # .text bounds
            text_start = text_end = None
            for block in memory.getBlocks():
                if block.getName() == ".text" or block.isExecute():
                    if text_start is None or block.getStart().getOffset() < text_start:
                        text_start = block.getStart().getOffset()
                    if text_end is None or block.getEnd().getOffset() > text_end:
                        text_end = block.getEnd().getOffset()
            print(f".text (SF 1.7): 0x{text_start:x} - 0x{text_end:x}")

            vtable_va_set = {v for v, _ in classes_sf17}

            n_total_slots = 0
            n_real_names = 0
            with open(OUT_CSV, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["class", "slot", "name"])
                for vt_va, cls in classes_sf17:
                    for slot_idx in range(DEFAULT_MAX_SLOTS):
                        try:
                            ptr_addr = default_space.getAddress(vt_va + slot_idx * 8)
                            ptr_val = memory.getLong(ptr_addr) & 0xFFFFFFFFFFFFFFFF
                        except Exception:
                            break
                        if ptr_val == 0:
                            break
                        if not (text_start <= ptr_val < text_end):
                            break
                        next_va = vt_va + (slot_idx + 1) * 8
                        if slot_idx > 0 and next_va in vtable_va_set:
                            # write this slot, then stop
                            func = fm.getFunctionContaining(default_space.getAddress(ptr_val))
                            if func is not None:
                                fn_name = func.getName(True)
                                fn_leaf = func.getName()
                                if not (fn_leaf.startswith("FUN_") or
                                        fn_leaf.startswith("thunk_FUN_") or
                                        fn_leaf.startswith("sub_")):
                                    w.writerow([cls, slot_idx, fn_name])
                                    n_real_names += 1
                            n_total_slots += 1
                            break
                        func = fm.getFunctionContaining(default_space.getAddress(ptr_val))
                        if func is not None:
                            fn_name = func.getName(True)
                            fn_leaf = func.getName()
                            if not (fn_leaf.startswith("FUN_") or
                                    fn_leaf.startswith("thunk_FUN_") or
                                    fn_leaf.startswith("sub_")):
                                w.writerow([cls, slot_idx, fn_name])
                                n_real_names += 1
                        n_total_slots += 1
            print(f"\nSlot scan complete:")
            print(f"  total slots scanned: {n_total_slots}")
            print(f"  with real names:     {n_real_names}")
            print(f"  wrote {OUT_CSV}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
