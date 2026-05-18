#!/usr/bin/env python3
"""Generic name-applier for any (project, program, CSV) tuple.

Usage:
  python apply_names_to_program.py <project_dir> <project_name> <program_path> <csv> [--commit-msg "msg"]

  project_dir   e.g. C:/GhidraProjects
  project_name  e.g. Combined
  program_path  forward-slash path inside the project, e.g. /Starfield/Starfield 1.16.236
                or just the program name to search-and-find anywhere
  csv           CSV with target_va,name columns (extra columns ignored)

Preserves hand-named work: only renames functions whose current name starts
with FUN_ / thunk_FUN_ / sub_.  Pre-creates ``::`` namespace paths in the
SymbolTable as needed.
"""
from __future__ import annotations

import csv
import os
import re
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = REPO_DIR / "tools" / "ghidra"

_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_<>$~?@-]")


def sanitize_component(part: str) -> str:
    part = part.strip()
    if not part:
        return "_"
    cleaned = _SAFE_COMPONENT_RE.sub("_", part)
    if cleaned and cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned or "_"


def split_namespaced(full: str) -> list[str]:
    parts = full.split("::")
    return [sanitize_component(p) for p in parts]


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)
    project_dir, project_name, program_path, csv_path = sys.argv[1:5]
    commit_msg = "Apply ported names"
    if "--commit-msg" in sys.argv:
        commit_msg = sys.argv[sys.argv.index("--commit-msg") + 1]

    if not Path(csv_path).is_file():
        print(f"ERROR: CSV missing: {csv_path}")
        sys.exit(2)

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.symbol import SourceType
    import java.lang
    monitor = ConsoleTaskMonitor()

    print(f"PROJECT: {project_dir}/{project_name}")
    print(f"PROGRAM: {program_path}")
    print(f"CSV:     {csv_path}")

    with pyghidra.open_project(project_dir, project_name, create=False) as project:
        root = project.getProjectData().getRootFolder()

        # Resolve program_path: either /folder/name or just a name to search for
        domain_file = None
        if program_path.startswith("/"):
            domain_file = project.getProjectData().getFile(program_path)
        if domain_file is None:
            # Fallback: walk and match by name
            target = program_path.lstrip("/").split("/")[-1]

            def walk(folder):
                for f in folder.getFiles():
                    if f.getName() == target:
                        return f
                for sub in folder.getFolders():
                    r = walk(sub)
                    if r is not None:
                        return r
                return None

            domain_file = walk(root)
        if domain_file is None:
            print(f"ERROR: program not found: {program_path}")
            sys.exit(3)
        print(f"Found program: {domain_file.getPathname()}")

        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, True, False, monitor)
        try:
            fm = program.getFunctionManager()
            sym = program.getSymbolTable()
            global_ns = program.getGlobalNamespace()
            addr_factory = program.getAddressFactory()
            default_space = addr_factory.getDefaultAddressSpace()

            txid = program.startTransaction(commit_msg)
            try:
                ns_cache = {}

                def get_or_create_namespace(path_parts):
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
                n_no_func = 0
                n_already_named = 0
                n_sanitize_fail = 0
                n_err = 0
                report_every = 1000

                with open(csv_path, encoding="utf-8") as fh:
                    reader = csv.DictReader(fh)
                    # Tolerate alt column names from BSim matcher CSV
                    name_col = None
                    for col in ("name", "source_name"):
                        if reader.fieldnames and col in reader.fieldnames:
                            name_col = col
                            break
                    if not name_col:
                        print(f"ERROR: no name column; have {reader.fieldnames}")
                        sys.exit(4)
                    for row in reader:
                        n_total += 1
                        try:
                            va_int = int(row["target_va"], 16)
                        except (KeyError, ValueError):
                            n_err += 1
                            continue
                        addr = default_space.getAddress(va_int)
                        func = fm.getFunctionAt(addr)
                        if func is None:
                            n_no_func += 1
                            continue
                        cur = func.getName()
                        if not (cur.startswith("FUN_") or cur.startswith("thunk_FUN_") or cur.startswith("sub_")):
                            n_already_named += 1
                            continue

                        parts = split_namespaced(row[name_col])
                        if not parts:
                            n_sanitize_fail += 1
                            continue
                        leaf = parts[-1]
                        ns_path = parts[:-1]
                        try:
                            target_ns = get_or_create_namespace(ns_path) if ns_path else global_ns
                            func.setParentNamespace(target_ns)
                            func.setName(leaf, SourceType.USER_DEFINED)
                            n_renamed += 1
                        except Exception as e:
                            n_err += 1
                            if n_err < 20:
                                print(f"  err at 0x{va_int:x} '{row[name_col][:60]}': {e}")

                        if n_total % report_every == 0:
                            print(f"  {n_total} processed  renamed={n_renamed}  "
                                  f"no_func={n_no_func}  already={n_already_named}  err={n_err}",
                                  flush=True)
            finally:
                program.endTransaction(txid, True)

            print(f"\nSaving program ...")
            program.save(commit_msg, monitor)
            print(f"\n=== Summary ===")
            print(f"  total CSV rows:      {n_total}")
            print(f"  functions renamed:   {n_renamed}")
            print(f"  no function at addr: {n_no_func}")
            print(f"  already named:       {n_already_named}")
            print(f"  sanitize fails:      {n_sanitize_fail}")
            print(f"  errors:              {n_err}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
