#!/usr/bin/env python3
"""Phase 3 of SF 1.7 -> SF 1.16.236 byte-sig naming port.

Applies ``refs/sf116_ported_names.csv`` (produced by Phase 2) onto the
Starfield.exe program in the BethesdaGhidraScripts headless project via
pyghidra.  Renames each function at its mapped target VA, sanitizing
names so Ghidra accepts them.

Strategy:
  - Open project, fetch Starfield.exe program (write access).
  - For each (target_va, name) row:
      - Find function at target_va; skip if none.
      - Skip already-named functions (preserve hand-named work).
      - Apply name as a parsed namespace path: split on "::" so each
        component becomes a Ghidra namespace, leaf is the function name.
        Sanitize each component to remove illegal chars.
  - Commit transaction, save, exit.
"""
from __future__ import annotations

import csv
import os
import re
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = REPO_DIR / "tools" / "ghidra"
PROJECT_DIR = REPO_DIR / "ghidraprojects" / "BethesdaGhidraScripts"
PROJECT_NAME = "BethesdaGhidraScripts"
PROGRAM_NAME = "Starfield.exe"
_DEFAULT_CSV = REPO_DIR / "scripts" / "commonlibsf" / "refs" / "sf116_ported_names.csv"
CSV_PATH     = Path(sys.argv[1]) if len(sys.argv) > 1 else _DEFAULT_CSV

# Ghidra symbol name policy:
#   * '::' is the namespace separator -- we want to honor that.
#   * Each name component should match [A-Za-z0-9_<>$~?@-]+ to be safe.
#     Spaces, backticks, commas, parens, single-quotes all cause issues.
#   * Replace problematic chars with '_'.
_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_<>$~?@-]")


def sanitize_component(part: str) -> str:
    """Make one path component safe for Ghidra's symbol parser."""
    part = part.strip()
    if not part:
        return "_"
    cleaned = _SAFE_COMPONENT_RE.sub("_", part)
    if cleaned and cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned or "_"


def split_namespaced(full: str) -> list[str]:
    """Split a C++-style name on '::' boundaries, sanitizing each part."""
    parts = full.split("::")
    return [sanitize_component(p) for p in parts]


def main():
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.symbol import SourceType
    import java.lang
    monitor = ConsoleTaskMonitor()

    print(f"PROJECT: {PROJECT_DIR}")
    print(f"PROGRAM: {PROGRAM_NAME}")
    print(f"CSV:     {CSV_PATH}")
    if not CSV_PATH.is_file():
        print("ERROR: CSV missing")
        sys.exit(2)

    with pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=False) as project:
        root = project.getProjectData().getRootFolder()

        def find(folder):
            for f in folder.getFiles():
                if f.getName() == PROGRAM_NAME:
                    return f
            for sub in folder.getFolders():
                r = find(sub)
                if r is not None:
                    return r
            return None

        domain_file = find(root)
        if domain_file is None:
            print(f"ERROR: {PROGRAM_NAME} not in project")
            sys.exit(3)
        print(f"Found program: {domain_file.getPathname()}")

        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, True, False, monitor)
        try:
            fm = program.getFunctionManager()
            sym = program.getSymbolTable()
            global_ns = program.getGlobalNamespace()
            ns_mgr = program.getNamespaceManager()
            addr_factory = program.getAddressFactory()
            default_space = addr_factory.getDefaultAddressSpace()

            txid = program.startTransaction("Apply SF 1.7 -> 1.16.236 ported names")
            try:
                # Pre-create namespaces lazily as we encounter them.
                ns_cache = {}

                def get_or_create_namespace(path_parts: list[str]):
                    """Walk a path like ['RE','PlayerCharacter'] returning
                    the deepest Namespace, creating parents as needed."""
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
                report_every = 500

                with open(CSV_PATH, encoding="utf-8") as fh:
                    reader = csv.DictReader(fh)
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
                        if not (cur.startswith("FUN_") or cur.startswith("thunk_FUN_")):
                            n_already_named += 1
                            continue

                        parts = split_namespaced(row["name"])
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
                                print(f"  err at 0x{va_int:x} '{row['name'][:60]}': {e}")

                        if n_total % report_every == 0:
                            print(f"  {n_total} processed  renamed={n_renamed}  "
                                  f"no_func={n_no_func}  already={n_already_named}  err={n_err}",
                                  flush=True)
            finally:
                program.endTransaction(txid, True)

            print(f"\nSaving program ...")
            program.save("SF 1.7 -> 1.16.236 byte-sig port", monitor)
            print(f"\n=== Summary ===")
            print(f"  total CSV rows:    {n_total}")
            print(f"  functions renamed: {n_renamed}")
            print(f"  no function at addr: {n_no_func}")
            print(f"  already named:     {n_already_named}")
            print(f"  sanitize fails:    {n_sanitize_fail}")
            print(f"  errors:            {n_err}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
