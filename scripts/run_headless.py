#!/usr/bin/env python3
"""
Headless PyGhidra runner — imports each .exe under exes/<game>/<version>/ into
a single shared Ghidra project and applies the matching CommonLibImport_*.py
script.

Usage:
  python scripts/run_headless.py                 # run all
  python scripts/run_headless.py skyrim          # all skyrim versions
  python scripts/run_headless.py skyrim ae       # specific
  python scripts/run_headless.py f4 ae

Layout:
  exes/skyrim/se/SkyrimSE.exe              -> CommonLibImport_SE.py
  exes/skyrim/ae/SkyrimSE.exe              -> CommonLibImport_AE.py
  exes/skyrim/vr/SkyrimVR.exe              -> CommonLibImport_VR.py
  exes/f4/og/Fallout4.exe                  -> CommonLibImport_F4_OG.py
  exes/f4/ng/Fallout4.exe                  -> CommonLibImport_F4_NG.py
  exes/f4/ae/Fallout4.exe                  -> CommonLibImport_F4_AE.py
  exes/f4/vr/Fallout4VR.exe                -> CommonLibImport_F4_VR.py

All binaries are stored in one Ghidra project under /<game>/<version>/ folders.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_DIR       = Path(__file__).parent.parent
GHIDRA_DIR     = REPO_DIR / "tools" / "ghidra"
EXES_ROOT      = REPO_DIR / "exes"
SCRIPTS_DIR    = REPO_DIR / "ghidrascripts"
PROJECTS_DIR   = REPO_DIR / "ghidraprojects"
STEAMLESS_CLI  = REPO_DIR / "tools" / "Steamless" / "Steamless.CLI.exe"

GHIDRA_PROJECT_NAME = "BethesdaGhidraScripts"

PROJECT_NAME = {
    'skyrim':    'SkyrimSE',
    'f4':        'Fallout4',
    'starfield': 'Starfield',
}

SPOT_CHECKS = {
    'skyrim': {
        'types': [
            ("Actor",           "/CommonLibSSE/RE", 680,  85),
            ("TESObjectREFR",   "/CommonLibSSE/RE", 140,  18),
            ("PlayerCharacter", "/CommonLibSSE/RE", 3000, 260),
            ("ActorValue",      "/CommonLibSSE/RE",    4,   0),
        ],
        'labels':    [],
        'functions': ["AbsorbEffect::ModifyOnStart", "AbsorbEffect::AdjustForPerks"],
        'min_named': 12000, 'min_enums': 300, 'min_structs': 4500, 'min_syms': 250000,
    },
    'f4': {
        'types': [
            ("ActorMovementData", "/CommonLibF4/RE", 70,  1),
            ("BGSEquipType",      "/CommonLibF4/RE", 10,  1),
            ("Actor_vtbl",        "/CommonLibF4/RE", 800, 100),
        ],
        # VTABLE_* labels live in the low/mid ID range and resolve in every
        # F4 address-library DB; RTTI_* labels use IDs >= 4M which only
        # exist in meh321's AE generation (and largely in NG).  Per-version
        # overrides below drop RTTI_* from the OG / VR / NG expectation.
        'labels':    ["VTABLE_Actor", "VTABLE_ActiveEffect", "RTTI_Actor"],
        'functions': [],
        'min_named': 200, 'min_enums': 100, 'min_structs': 500, 'min_syms': 0,
    },
    'starfield': {
        # CommonLibSF uses C++23 features that may defeat the AST parse
        # on first run; if so the script emits labels-only and these type
        # spot-checks are skipped (set to [] until the parse is verified).
        # Once CommonLibSF parses cleanly, restore representative types here.
        'types':     [],
        'labels':    ["RTTI_Actor", "VTABLE_Actor"],
        'functions': [],
        'min_named': 1000, 'min_enums': 0, 'min_structs': 0, 'min_syms': 0,
    },
}


# Per-version overlays applied on top of the per-game baseline.  RTTI_* IDs
# (>= 4M) only exist in meh321's AE address library generation, so the
# other F4 patches drop that label expectation.  OG / VR also have weaker
# function-name coverage than AE/NG (some names come from cross-version
# byte-sig porting), so the min_named floor is lowered to a value attainable
# with the byte-sig pass alone.
SPOT_CHECKS_OVERRIDES = {
    ('f4', 'og'): {
        'labels':    ["VTABLE_Actor", "VTABLE_ActiveEffect"],
        'min_named': 100,
    },
    ('f4', 'ng'): {
        'labels':    ["VTABLE_Actor", "VTABLE_ActiveEffect"],
    },
    ('f4', 'vr'): {
        'labels':    ["VTABLE_Actor", "VTABLE_ActiveEffect"],
        'min_named': 100,
    },
}


sys.path.insert(0, str(REPO_DIR / "scripts" / "core"))
from steamless import ensure_unpacked as _ensure_unpacked_impl  # noqa: E402


def _ensure_unpacked(binary: Path) -> Path:
    return _ensure_unpacked_impl(binary, STEAMLESS_CLI)


def script_for(game: str, version: str) -> Path:
    if game == 'f4':
        return SCRIPTS_DIR / f"CommonLibImport_F4_{version.upper()}.py"
    if game == 'starfield':
        # Single-version pipeline; <version> directory name (e.g. "sf" or
        # "1-16-236-0") is ignored at script-lookup time.
        return SCRIPTS_DIR / "CommonLibImport_SF.py"
    return SCRIPTS_DIR / f"CommonLibImport_{version.upper()}.py"


def discover_targets(filter_game=None, filter_ver=None):
    targets = []
    if not EXES_ROOT.is_dir():
        return targets
    for game_dir in sorted(EXES_ROOT.iterdir()):
        if not game_dir.is_dir():
            continue
        game = game_dir.name
        if filter_game and filter_game != game:
            continue
        for ver_dir in sorted(game_dir.iterdir()):
            if not ver_dir.is_dir():
                continue
            version = ver_dir.name
            if filter_ver and filter_ver != version:
                continue
            exes = sorted(ver_dir.glob("*.exe"))
            if not exes:
                continue
            targets.append((game, version, exes[0]))
    return targets


def _verify(program, game, version):
    fm        = program.getFunctionManager()
    dtm       = program.getDataTypeManager()
    sym_table = program.getSymbolTable()
    spec = dict(SPOT_CHECKS[game])
    override = SPOT_CHECKS_OVERRIDES.get((game, version))
    if override:
        spec.update(override)

    total_funcs  = fm.getFunctionCount()
    named_funcs  = sum(1 for f in fm.getFunctions(True)
                       if not f.getName().startswith("FUN_") and not f.getName().startswith("sub_"))
    scoped_funcs = sum(1 for f in fm.getFunctions(True) if "::" in f.getName())
    enum_count = struct_count = 0
    for dt in dtm.getAllDataTypes():
        s = dt.getClass().getSimpleName()
        if s == "EnumDB":         enum_count   += 1
        elif s == "StructureDB":  struct_count += 1
    sym_count    = sum(1 for _ in sym_table.getAllSymbols(True))
    sigs_applied = sum(1 for f in fm.getFunctions(True)
                       if f.getSignature().getReturnType().getClass().getSimpleName() != "DefaultDataType")

    print("\n=== Verification Summary ===")
    print(f"  Total functions       : {total_funcs:>8,}")
    print(f"  Named functions       : {named_funcs:>8,}")
    print(f"    Scoped (Class::Fn)  : {scoped_funcs:>8,}")
    print(f"  Signatures set        : {sigs_applied:>8,}")
    print(f"    Enums               : {enum_count:>8,}")
    print(f"    Structs/Classes     : {struct_count:>8,}")
    print(f"  Total symbols         : {sym_count:>8,}")

    spot_ok = True

    if spec['types']:
        print("\n--- Type spot-checks ---")
        from ghidra.program.model.data import CategoryPath
        for type_name, cat_path, min_bytes, min_comps in spec['types']:
            dt = dtm.getDataType(CategoryPath(cat_path), type_name)
            if dt is None:
                print(f"  MISSING: {type_name} in {cat_path}")
                spot_ok = False
            else:
                comps = dt.getComponents() if hasattr(dt, "getComponents") else []
                size  = dt.getLength()
                ok    = size >= min_bytes and len(comps) >= min_comps
                mark  = "OK" if ok else "FAIL"
                named = len([x for x in comps if x.getFieldName()])
                print(f"  [{mark}] {type_name}: {size} bytes, {len(comps)} components ({named} named)")
                if not ok:
                    spot_ok = False

    if spec['labels']:
        print("\n--- Label spot-checks ---")
        for lname in spec['labels']:
            syms = list(sym_table.getSymbols(lname))
            if syms:
                print(f"  [OK] {lname} @ {syms[0].getAddress()}")
            else:
                print(f"  [MISSING] {lname}")
                spot_ok = False

    if spec['functions']:
        print("\n--- Function spot-checks ---")
        for fname in spec['functions']:
            syms = list(sym_table.getSymbols(fname))
            if syms:
                f = fm.getFunctionAt(syms[0].getAddress())
                ret    = f.getReturnType().getName() if f else "?"
                params = f.getParameterCount()       if f else "?"
                print(f"  [OK] {fname} @ {syms[0].getAddress()} ret={ret} params={params}")
            else:
                print(f"  [MISSING] {fname}")
                spot_ok = False

    print("\n--- Sanity checks ---")
    errors = []
    if named_funcs < spec['min_named']:
        errors.append(f"Named functions too low: {named_funcs:,} (expected >={spec['min_named']:,})")
    if enum_count < spec['min_enums']:
        errors.append(f"Enum count too low: {enum_count} (expected >={spec['min_enums']})")
    if struct_count < spec['min_structs']:
        errors.append(f"Struct count too low: {struct_count} (expected >={spec['min_structs']})")
    if spec['min_syms'] and sym_count < spec['min_syms']:
        errors.append(f"Symbol count too low: {sym_count:,} (expected >={spec['min_syms']:,})")
    if not spot_ok:
        errors.append("One or more spot-checks failed (see above)")

    if errors:
        print("\n!!! VERIFICATION FAILURES !!!")
        for e in errors:
            print(f"  - {e}")
        return False
    print("\nAll verification checks passed.")
    return True


def _get_folder(root_folder, game, version):
    """Get or create /<game>/<version>/ folder in the project."""
    game_folder = root_folder.getFolder(game)
    if game_folder is None:
        game_folder = root_folder.createFolder(game)
    ver_folder = game_folder.getFolder(version)
    if ver_folder is None:
        ver_folder = game_folder.createFolder(version)
    return ver_folder


def _run_one(project, game, version, binary, script_path, monitor):
    from ghidra.app.util.importer import MessageLog
    import ghidra
    import java.io
    import java.lang
    import pyghidra

    root_folder = project.getProjectData().getRootFolder()
    folder = _get_folder(root_folder, game, version)
    folder_path = f"/{game}/{version}"
    project_name = PROJECT_NAME[game]

    domain_file = None
    for cand in (binary.name, binary.stem, project_name):
        domain_file = folder.getFile(cand)
        if domain_file is not None:
            break

    if domain_file is None:
        print(f"Importing {binary} ...")
        msg_log         = MessageLog()
        jfile           = java.io.File(str(binary))
        import_consumer = java.lang.Object()
        load_results = ghidra.app.util.importer.AutoImporter.importByUsingBestGuess(
            jfile, project, folder_path, import_consumer, msg_log, monitor
        )
        if not load_results:
            raise RuntimeError("Import returned no results.")
        print(f"Import complete. Loaded {load_results.size()} program(s).")
        load_results.save(monitor)
        load_results.close()
        for cand in (binary.name, binary.stem, project_name):
            domain_file = folder.getFile(cand)
            if domain_file is not None:
                break
        if domain_file is None:
            files = [f.getName() for f in folder.getFiles()]
            if not files:
                raise RuntimeError("No files found in project after import.")
            domain_file = folder.getFile(files[0])
    else:
        print(f"Program '{domain_file.getName()}' already in project, skipping import.")

    consumer = java.lang.Object()
    program  = domain_file.getDomainObject(consumer, True, False, monitor)
    try:
        print(f"Running {script_path.name} ...")
        stdout, stderr = pyghidra.ghidra_script(
            script_path, project, program, echo_stdout=False, echo_stderr=False)
        if stdout: print(stdout)
        if stderr: print("STDERR:", stderr, file=sys.stderr)
        program.save(f"CommonLib {game} {version} import", monitor)
        print("Saved.")
        return _verify(program, game, version)
    finally:
        program.release(consumer)


def main():
    args  = sys.argv[1:]
    fg    = args[0] if len(args) > 0 else None
    fv    = args[1] if len(args) > 1 else None
    targets = discover_targets(fg, fv)
    if not targets:
        print(f"No targets found in {EXES_ROOT}")
        sys.exit(1)

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    monitor = ConsoleTaskMonitor()

    project_dir = PROJECTS_DIR / GHIDRA_PROJECT_NAME
    project_dir.mkdir(parents=True, exist_ok=True)

    gpr = project_dir / f"{GHIDRA_PROJECT_NAME}.gpr"
    rep = project_dir / f"{GHIDRA_PROJECT_NAME}.rep"
    if rep.exists() and not gpr.exists():
        shutil.rmtree(rep)

    failures = []
    try:
        with pyghidra.open_project(project_dir, GHIDRA_PROJECT_NAME, create=True) as project:
            for game, version, binary in targets:
                print("\n" + "=" * 60)
                print(f"  {game.upper()} / {version.upper()}: {binary}")
                print("=" * 60)
                binary = _ensure_unpacked(binary)
                script_path = script_for(game, version)
                if not script_path.is_file():
                    print(f"SKIP: script not found at {script_path}")
                    failures.append((game, version, "missing script"))
                    continue
                try:
                    ok = _run_one(project, game, version, binary, script_path, monitor)
                    if not ok:
                        failures.append((game, version, "verification failed"))
                except Exception as e:
                    print(f"ERROR: {e}")
                    failures.append((game, version, str(e)))
    except Exception as e:
        print(f"ERROR opening project: {e}")
        sys.exit(1)

    print("\n" + "=" * 60)
    if failures:
        print("FAILURES:")
        for g, v, msg in failures:
            print(f"  {g}/{v}: {msg}")
        sys.exit(1)
    print(f"All {len(targets)} headless run(s) passed.")


if __name__ == "__main__":
    main()
