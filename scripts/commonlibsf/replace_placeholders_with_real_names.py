#!/usr/bin/env python3
"""Rename SF 1.16 ``Class::Func{N}`` placeholder functions to real
method names extracted from SF 1.7 vtables.

Pipeline:
  - Load sf17_vtable_slot_names.csv -> mapping (class, slot) -> real_name
  - Skip any 'real_name' that is itself FuncN-style (placeholder noise)
  - In Combined.gpr/Starfield 1.16.236, for each function whose name is
    'Class::FuncN', look up (class, N).  If we have a real_name, rename.

Output:
  - Renames in Ghidra
  - Console: counts of renames / skips / conflicts
"""
from __future__ import annotations

import csv
import os
import re
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = REPO_DIR / "tools" / "ghidra"

PROJECT_DIR  = "C:/GhidraProjects"
PROJECT_NAME = "Combined"
PROGRAM_PATH = "/Starfield/Starfield 1.16.236"

SF17_SLOTS = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf17_vtable_slot_names.csv"

_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_<>$~?@-]")
_FUNC_N_RE         = re.compile(r"^Func\d+$")
_LEAF_FUNC_N_RE    = re.compile(r"^Func(\d+)$")
_CLASS_FUNC_RE     = re.compile(r"(.+)::Func(\d+)$")


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


def main():
    # Step 1: load slot -> real_name map
    slot_map = {}      # (class_name, slot_idx) -> set of real_name candidates
    n_loaded = 0
    n_placeholder = 0
    with open(SF17_SLOTS, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cls = row["class"].strip()
            try:
                slot = int(row["slot"])
            except ValueError:
                continue
            name = row["name"].strip()
            # 'name' is a full qualified name like 'Actor::PlayPickUpSound'
            # We need to filter out placeholder-only names.
            leaf = name.split("::")[-1]
            if _FUNC_N_RE.match(leaf):
                n_placeholder += 1
                continue
            slot_map.setdefault((cls, slot), set()).add(name)
            n_loaded += 1
    print(f"Loaded SF 1.7 slot names: {n_loaded} entries  ({n_placeholder} placeholders skipped)")
    print(f"  unique (class, slot) keys: {len(slot_map)}")

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.symbol import SourceType
    import java.lang
    monitor = ConsoleTaskMonitor()

    with pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=False) as project:
        domain_file = project.getProjectData().getFile(PROGRAM_PATH)
        if domain_file is None:
            print(f"ERROR: program not found: {PROGRAM_PATH}")
            sys.exit(2)
        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, True, False, monitor)
        try:
            fm = program.getFunctionManager()
            sym = program.getSymbolTable()
            global_ns = program.getGlobalNamespace()

            txid = program.startTransaction("Replace Func{N} placeholders with SF 1.7 real names")
            try:
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
                            sub = sym.createNameSpace(parent, part, SourceType.USER_DEFINED)
                        parent = sub
                    ns_cache[key] = parent
                    return parent

                n_total = 0
                n_renamed = 0
                n_no_mapping = 0
                n_ambiguous = 0
                n_err = 0
                report_every = 5000

                # Iterate ALL functions; pick the placeholders
                for func in fm.getFunctions(True):
                    leaf = func.getName()
                    n_total += 1
                    m = _LEAF_FUNC_N_RE.match(leaf)
                    if not m:
                        continue
                    slot_idx = int(m.group(1))
                    # The class is the parent namespace path
                    parent_ns = func.getParentNamespace()
                    if parent_ns is None or parent_ns == global_ns:
                        continue
                    # Reconstruct class name from namespace hierarchy
                    parts = []
                    ns = parent_ns
                    while ns is not None and ns != global_ns:
                        parts.append(ns.getName())
                        ns = ns.getParentNamespace()
                    cls_name = "::".join(reversed(parts))

                    candidates = slot_map.get((cls_name, slot_idx))
                    if not candidates:
                        n_no_mapping += 1
                        continue
                    if len(candidates) > 1:
                        n_ambiguous += 1
                        continue
                    real_name = next(iter(candidates))
                    # Split into namespace path + leaf
                    new_parts = split_namespaced(real_name)
                    new_leaf = new_parts[-1]
                    new_ns_path = new_parts[:-1]
                    try:
                        target_ns = get_or_create_namespace(new_ns_path)
                        func.setParentNamespace(target_ns)
                        func.setName(new_leaf, SourceType.USER_DEFINED)
                        n_renamed += 1
                    except Exception as e:
                        n_err += 1
                        if n_err < 10:
                            print(f"  err renaming {cls_name}::Func{slot_idx} -> {real_name}: {e}")

                    if n_renamed % report_every == 0 and n_renamed > 0:
                        print(f"  renamed={n_renamed}  no_map={n_no_mapping}  ambig={n_ambiguous}", flush=True)
            finally:
                program.endTransaction(txid, True)

            print(f"\nSaving program ...")
            program.save("Replace Func{N} placeholders with SF 1.7 real names", monitor)
            print(f"\n=== Summary ===")
            print(f"  total funcs scanned:   {n_total}")
            print(f"  renamed:               {n_renamed}")
            print(f"  no mapping for slot:   {n_no_mapping}")
            print(f"  ambiguous:             {n_ambiguous}")
            print(f"  errors:                {n_err}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
