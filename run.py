#!/usr/bin/env python3
"""
Interactive launcher for Bethesda Ghidra Scripts.

Presents a menu of actions: update submodules, rebuild import scripts,
run the headless Ghidra import, open Ghidra, etc.

Usage:
  python run.py            Interactive menu
  python run.py setup      Install prerequisites + tools (non-interactive)
  python run.py build      Generate scripts + headless import (non-interactive)
  python run.py all        Full pipeline: setup + build + open Ghidra
"""
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

REPO_DIR      = Path(__file__).resolve().parent
EXES_ROOT     = REPO_DIR / "exes"
SCRIPTS_DIR   = REPO_DIR / "scripts"
TOOLS_DIR     = REPO_DIR / "tools"
GHIDRA_DIR    = TOOLS_DIR / "ghidra"
STEAMLESS_DIR = TOOLS_DIR / "Steamless"
LLVM_DIR      = TOOLS_DIR / "llvm"

GHIDRA_SCRIPTS_DIR  = REPO_DIR / "ghidrascripts"
PROJECTS_DIR        = REPO_DIR / "ghidraprojects"
GHIDRA_PROJECT_NAME = "BethesdaGhidraScripts"
STATE_FILE          = REPO_DIR / ".last_run_state"

GHIDRA_RELEASES_URL    = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
STEAMLESS_RELEASES_URL = "https://api.github.com/repos/atom0s/Steamless/releases/latest"
LLVM_RELEASES_URL      = "https://api.github.com/repos/llvm/llvm-project/releases/latest"

REQUIRED_PACKAGES = {
    "pdbparse": "pdbparse",
    "pyghidra": "pyghidra",
    # capstone + numpy are only consumed by scripts/commonlibf4/run_bytesig_port.py
    # for the masked-retry pass that wildcards rel32 / rip-rel operands on
    # cross-build matches (AE -> OG / VR).  Without them the byte-sig port still
    # works for exact 32-byte matches; masked Pass 2 is skipped with a notice.
    "capstone": "capstone",
    "numpy":    "numpy",
}

API_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "BethesdaGhidraScripts",
}


# =====================================================================
#  Helpers
# =====================================================================

def _header(msg):
    print(f"\n{'=' * 60}\n  {msg}\n{'=' * 60}")


def _download(url, dest, label="Downloading"):
    with urllib.request.urlopen(url) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        done = 0
        with open(dest, "wb") as f:
            while chunk := resp.read(1024 * 1024):
                f.write(chunk)
                done += len(chunk)
                if total:
                    print(f"\r  {label}: {done * 100 // total}%", end="", flush=True)
        if total:
            print()


def _can_import(name):
    try:
        __import__(name)
        return True
    except ImportError:
        return False


# =====================================================================
#  Status detection
# =====================================================================

def _ghidra_version(path):
    props = path / "Ghidra" / "application.properties"
    if props.is_file():
        for line in props.read_text().splitlines():
            if line.startswith("application.version="):
                return line.split("=", 1)[1]
    return None


def _clang_version():
    clang_name = "clang.exe" if sys.platform == "win32" else "clang"
    local_clang = LLVM_DIR / "bin" / clang_name
    if local_clang.is_file():
        os.environ["PATH"] = str(LLVM_DIR / "bin") + os.pathsep + os.environ.get("PATH", "")
    try:
        r = subprocess.run(
            ["clang", "--version"], capture_output=True, text=True, check=True)
        return r.stdout.strip().splitlines()[0]
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def _discover_exes():
    """Return list of (game, version, exe_path) tuples."""
    found = []
    if not EXES_ROOT.is_dir():
        return found
    for game_dir in sorted(EXES_ROOT.iterdir()):
        if not game_dir.is_dir():
            continue
        for ver_dir in sorted(game_dir.iterdir()):
            if not ver_dir.is_dir():
                continue
            exes = [f for f in sorted(ver_dir.glob("*.exe"))
                    if "unpacked" not in f.name.lower()]
            if exes:
                found.append((game_dir.name, ver_dir.name, exes[0]))
    return found


def _discover_games():
    return {g for g, _, _ in _discover_exes()}


def _project_exists():
    gpr = PROJECTS_DIR / GHIDRA_PROJECT_NAME / f"{GHIDRA_PROJECT_NAME}.gpr"
    return gpr.is_file()


def _scripts_exist(games):
    # One parse pass per game emits scripts for every version that game's
    # CommonLib + address libraries support, so check the full set.
    if "skyrim" in games:
        for name in ("CommonLibImport_SE.py",
                     "CommonLibImport_AE.py",
                     "CommonLibImport_VR.py"):
            if not (GHIDRA_SCRIPTS_DIR / name).is_file():
                return False
    if "f4" in games:
        for name in ("CommonLibImport_F4_OG.py",
                     "CommonLibImport_F4_NG.py",
                     "CommonLibImport_F4_AE.py",
                     "CommonLibImport_F4_VR.py"):
            if not (GHIDRA_SCRIPTS_DIR / name).is_file():
                return False
    return True


def _get_submodule_hashes():
    r = subprocess.run(
        ["git", "submodule", "status", "--recursive"],
        cwd=str(REPO_DIR), capture_output=True, text=True, check=True)
    hashes = {}
    for line in r.stdout.strip().splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            hashes[parts[1]] = parts[0].lstrip("+-")
    return hashes


def _get_exe_fingerprints():
    fps = {}
    if EXES_ROOT.is_dir():
        for exe in EXES_ROOT.rglob("*.exe"):
            if "unpacked" in exe.name:
                continue
            rel = exe.relative_to(EXES_ROOT).as_posix()
            st = exe.stat()
            fps[rel] = {"mtime": st.st_mtime, "size": st.st_size}
    return fps


def _load_state():
    if STATE_FILE.is_file():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_state(submodules, exes):
    STATE_FILE.write_text(json.dumps(
        {"submodules": submodules, "exes": exes}, indent=2))


# =====================================================================
#  Actions
# =====================================================================

def check_prerequisites():
    _header("Prerequisites")
    if sys.version_info < (3, 10):
        print(f"  ERROR: Python 3.10+ required (found {sys.version})")
        sys.exit(1)
    print(f"  Python {sys.version.split()[0]}")

    missing = [pkg for imp, pkg in REQUIRED_PACKAGES.items()
               if not _can_import(imp)]
    if missing:
        print(f"  Installing: {', '.join(missing)} ...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", *missing])
    print("  Python packages: OK")


def update_submodules():
    _header("Update Submodules")
    subprocess.run(
        ["git", "submodule", "update", "--init", "--recursive", "--remote"],
        cwd=str(REPO_DIR), check=True)
    print("  Up to date.")


def setup_ghidra():
    _header("Ghidra")

    old_ghidra = REPO_DIR / "ghidra"
    if not GHIDRA_DIR.exists() and old_ghidra.exists() and _ghidra_version(old_ghidra):
        print("  Migrating Ghidra to tools/ ...")
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        shutil.move(str(old_ghidra), str(GHIDRA_DIR))

    ver = _ghidra_version(GHIDRA_DIR)
    if ver:
        print(f"  Ghidra {ver} (installed)")
        return

    print("  Fetching latest release ...")
    req = urllib.request.Request(GHIDRA_RELEASES_URL, headers=API_HEADERS)
    with urllib.request.urlopen(req) as resp:
        release = json.loads(resp.read())

    asset = next(
        (a for a in release.get("assets", [])
         if a["name"].endswith(".zip") and "ghidra" in a["name"].lower()),
        None)
    if not asset:
        print("  ERROR: no Ghidra zip found in latest release")
        sys.exit(1)

    size_mb = asset.get("size", 0) / 1024 / 1024
    print(f"  {asset['name']} ({size_mb:.0f} MB)")

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _download(asset["browser_download_url"], tmp_path)
        print("  Extracting ...")
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(tmp_path) as zf:
                zf.extractall(tmpdir)
            roots = [p for p in Path(tmpdir).iterdir() if p.is_dir()]
            src = roots[0] if len(roots) == 1 else Path(tmpdir)
            TOOLS_DIR.mkdir(parents=True, exist_ok=True)
            if GHIDRA_DIR.exists():
                shutil.rmtree(GHIDRA_DIR)
            shutil.copytree(str(src), str(GHIDRA_DIR))
    finally:
        tmp_path.unlink(missing_ok=True)

    ver = _ghidra_version(GHIDRA_DIR)
    print(f"  Ghidra {ver or '?'} installed")


def setup_steamless():
    if sys.platform != "win32":
        return

    _header("Steamless")
    cli = STEAMLESS_DIR / "Steamless.CLI.exe"
    if cli.is_file():
        print("  Steamless CLI: OK")
        return

    print("  Fetching latest release ...")
    req = urllib.request.Request(STEAMLESS_RELEASES_URL, headers=API_HEADERS)
    try:
        with urllib.request.urlopen(req) as resp:
            release = json.loads(resp.read())
    except Exception as e:
        print(f"  WARNING: could not fetch Steamless ({e}); DRM removal skipped")
        return

    asset = next(
        (a for a in release.get("assets", []) if a["name"].endswith(".zip")),
        None)
    if not asset:
        print("  WARNING: no zip in latest release; DRM removal skipped")
        return

    print(f"  {asset['name']}")
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _download(asset["browser_download_url"], tmp_path)
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(tmp_path) as zf:
                zf.extractall(tmpdir)
            hits = list(Path(tmpdir).rglob("Steamless.CLI.exe"))
            if not hits:
                print("  WARNING: Steamless.CLI.exe not found in archive")
                return
            src = hits[0].parent
            STEAMLESS_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copytree(str(src), str(STEAMLESS_DIR), dirs_exist_ok=True)
    finally:
        tmp_path.unlink(missing_ok=True)

    print("  Steamless CLI installed")


def _ensure_clang():
    clang_name = "clang.exe" if sys.platform == "win32" else "clang"
    local_clang = LLVM_DIR / "bin" / clang_name

    if local_clang.is_file():
        os.environ["PATH"] = str(LLVM_DIR / "bin") + os.pathsep + os.environ["PATH"]
        ver = _clang_version()
        if ver:
            print(f"  {ver}")
            return

    ver = _clang_version()
    if ver:
        print(f"  {ver}")
        return

    _download_llvm()
    os.environ["PATH"] = str(LLVM_DIR / "bin") + os.pathsep + os.environ["PATH"]
    ver = _clang_version()
    if ver:
        print(f"  {ver}")
    else:
        print("  ERROR: clang not working after LLVM install")
        sys.exit(1)


def _download_llvm():
    print("  clang not found; downloading LLVM ...")

    req = urllib.request.Request(LLVM_RELEASES_URL, headers=API_HEADERS)
    with urllib.request.urlopen(req) as resp:
        release = json.loads(resp.read())

    if sys.platform == "win32":
        machine = platform.machine().lower()
        arch = "x86_64" if machine in ("amd64", "x86_64") else "aarch64"
        suffix = f"{arch}-pc-windows-msvc.tar.xz"
    elif sys.platform == "darwin":
        machine = platform.machine().lower()
        arch = "ARM64" if machine == "arm64" else "X64"
        suffix = f"macOS-{arch}.tar.xz"
    else:
        machine = platform.machine().lower()
        arch = "ARM64" if machine == "aarch64" else "X64"
        suffix = f"Linux-{arch}.tar.xz"

    asset = next(
        (a for a in release.get("assets", [])
         if a["name"].endswith(suffix) and a["name"].endswith(".tar.xz")),
        None)
    if not asset:
        print(f"  ERROR: no LLVM asset matching *{suffix}")
        print("  Install LLVM/Clang manually and add clang to PATH.")
        sys.exit(1)

    size_mb = asset.get("size", 0) / 1024 / 1024
    print(f"  {asset['name']} ({size_mb:.0f} MB)")

    with tempfile.NamedTemporaryFile(suffix=".tar.xz", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _download(asset["browser_download_url"], tmp_path)
        print("  Extracting (this may take several minutes) ...")
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tmp_path, "r:xz") as tar:
            try:
                tar.extractall(TOOLS_DIR, filter="data")
            except TypeError:
                tar.extractall(TOOLS_DIR)
        for d in TOOLS_DIR.iterdir():
            if d.is_dir() and d != LLVM_DIR and (
                    "clang+llvm" in d.name or "LLVM" in d.name):
                if LLVM_DIR.exists():
                    shutil.rmtree(LLVM_DIR)
                d.rename(LLVM_DIR)
                break
    finally:
        tmp_path.unlink(missing_ok=True)

    clang_name = "clang.exe" if sys.platform == "win32" else "clang"
    if not (LLVM_DIR / "bin" / clang_name).is_file():
        print("  ERROR: clang not found after LLVM extraction")
        sys.exit(1)
    print("  LLVM installed")


def generate_scripts(games=None):
    if games is None:
        games = _discover_games()
    if not games:
        print("  No executables found -- nothing to generate.")
        return

    _header("Generating Import Scripts")
    _ensure_clang()

    if "skyrim" in games:
        print("  Skyrim SE / AE / VR ...")
        subprocess.run(
            [sys.executable,
             str(SCRIPTS_DIR / "commonlibsse" / "parse_commonlib_types.py")],
            cwd=str(REPO_DIR), check=True)
    if "f4" in games:
        print("  Fallout 4 OG / NG / AE / VR ...")
        subprocess.run(
            [sys.executable,
             str(SCRIPTS_DIR / "commonlibf4" / "parse_commonlib_types.py")],
            cwd=str(REPO_DIR), check=True)
        # F4 OG and VR use disjoint ID namespaces from NG/AE -- CommonLibF4
        # IDs don't resolve there.  When AE (or NG) and OG/VR binaries are
        # both present, port AE-known function names across via masked
        # byte-signature matching so OG/VR scripts apply function names
        # instead of types-only.  Skipped when the helper script isn't
        # present (e.g. on a branch where the F4 OG/NG/VR support hasn't
        # landed yet); no-op when AE/NG inputs aren't installed.
        bytesig_port = SCRIPTS_DIR / "commonlibf4" / "run_bytesig_port.py"
        if bytesig_port.is_file():
            print("  Fallout 4 cross-version byte-signature port ...")
            subprocess.run(
                [sys.executable, str(bytesig_port)],
                cwd=str(REPO_DIR), check=False)


def run_headless():
    _header("Headless Ghidra Import")
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "run_headless.py")],
        cwd=str(REPO_DIR)).returncode


def launch_ghidra():
    _header("Launching Ghidra")
    if sys.platform == "win32":
        launcher = GHIDRA_DIR / "ghidraRun.bat"
    else:
        launcher = GHIDRA_DIR / "ghidraRun"
    if not launcher.is_file():
        print(f"  WARNING: {launcher.name} not found")
        return

    project_dir = PROJECTS_DIR / GHIDRA_PROJECT_NAME
    gpr = project_dir / f"{GHIDRA_PROJECT_NAME}.gpr"

    lock = project_dir / f"{GHIDRA_PROJECT_NAME}.lock"
    if lock.exists():
        try:
            lock.unlink()
        except OSError:
            pass

    print(f"  Project: {project_dir.relative_to(REPO_DIR)}/")
    if sys.platform == "win32":
        subprocess.Popen(
            [str(launcher), str(gpr)],
            cwd=str(GHIDRA_DIR),
            creationflags=subprocess.CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
    else:
        subprocess.Popen(
            [str(launcher), str(gpr)],
            cwd=str(GHIDRA_DIR),
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)


def clean_project():
    _header("Clean Ghidra Project")
    project_dir = PROJECTS_DIR / GHIDRA_PROJECT_NAME
    if project_dir.exists():
        shutil.rmtree(project_dir)
        print("  Removed project directory.")
    if STATE_FILE.is_file():
        STATE_FILE.unlink()
        print("  Removed state file.")
    print("  Done. Next import will start fresh.")


# =====================================================================
#  Status display
# =====================================================================

def _print_status():
    """Print current environment status and return (games, status_lines)."""
    print()
    print("=" * 60)
    print("  Bethesda Ghidra Scripts")
    print("=" * 60)

    # Tools
    ghidra_ver = _ghidra_version(GHIDRA_DIR)
    clang_ver = _clang_version()
    steamless_ok = (STEAMLESS_DIR / "Steamless.CLI.exe").is_file()
    pkgs_ok = all(_can_import(imp) for imp in REQUIRED_PACKAGES)

    print()
    print("  Tools:")
    print(f"    Ghidra      : {ghidra_ver or 'not installed'}")
    print(f"    Clang       : {clang_ver or 'not installed'}")
    if sys.platform == "win32":
        print(f"    Steamless   : {'OK' if steamless_ok else 'not installed'}")
    print(f"    Python pkgs : {'OK' if pkgs_ok else 'missing'}")

    # Executables
    exes = _discover_exes()
    games = {g for g, _, _ in exes}
    print()
    print("  Executables:")
    if exes:
        for game, ver, exe in exes:
            print(f"    {game}/{ver}: {exe.name}")
    else:
        print("    (none found)")

    # Generated scripts
    has_scripts = _scripts_exist(games) if games else False
    has_project = _project_exists()
    print()
    print("  Output:")
    print(f"    Import scripts : {'OK' if has_scripts else 'not generated'}")
    print(f"    Ghidra project : {'OK' if has_project else 'not created'}")

    return games


# =====================================================================
#  Menu
# =====================================================================

MENU_ITEMS = [
    ("1", "Install prerequisites (Python packages, Ghidra, Clang, Steamless)"),
    ("2", "Update CommonLib submodules to latest"),
    ("3", "Generate import scripts"),
    ("4", "Run headless Ghidra import"),
    ("5", "Open Ghidra"),
    ("6", "Full rebuild (generate + import)"),
    ("7", "Clean Ghidra project (start fresh)"),
    ("q", "Quit"),
]


def _show_menu():
    print()
    print("-" * 40)
    for key, label in MENU_ITEMS:
        print(f"  {key}) {label}")
    print("-" * 40)


def _run_menu():
    games = _print_status()
    _show_menu()

    while True:
        try:
            choice = input("\n  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice == "q":
            break
        elif choice == "1":
            check_prerequisites()
            setup_ghidra()
            setup_steamless()
            _ensure_clang()
        elif choice == "2":
            update_submodules()
        elif choice == "3":
            games = _discover_games()
            generate_scripts(games)
        elif choice == "4":
            rc = run_headless()
            if rc == 0:
                _save_state(_get_submodule_hashes(), _get_exe_fingerprints())
        elif choice == "5":
            launch_ghidra()
            break
        elif choice == "6":
            games = _discover_games()
            generate_scripts(games)
            rc = run_headless()
            if rc == 0:
                _save_state(_get_submodule_hashes(), _get_exe_fingerprints())
        elif choice == "7":
            clean_project()
        else:
            print("  Invalid choice.")
            continue

        games = _print_status()
        _show_menu()


# =====================================================================
#  CLI subcommands for non-interactive use
# =====================================================================

def _cmd_setup():
    check_prerequisites()
    update_submodules()
    setup_ghidra()
    setup_steamless()


def _cmd_build():
    games = _discover_games()
    if not games:
        print("No executables found.")
        sys.exit(1)
    generate_scripts(games)
    rc = run_headless()
    if rc == 0:
        _save_state(_get_submodule_hashes(), _get_exe_fingerprints())
    sys.exit(rc)


def _cmd_all():
    _cmd_setup()
    games = _discover_games()
    if not games:
        print("No executables found.")
        sys.exit(1)
    generate_scripts(games)
    rc = run_headless()
    if rc == 0:
        _save_state(_get_submodule_hashes(), _get_exe_fingerprints())
    launch_ghidra()
    sys.exit(rc)


def main():
    args = sys.argv[1:]
    if not args:
        _run_menu()
    elif args[0] == "setup":
        _cmd_setup()
    elif args[0] == "build":
        _cmd_build()
    elif args[0] == "all":
        _cmd_all()
    else:
        print(f"Unknown command: {args[0]}")
        print("Usage: python run.py [setup|build|all]")
        sys.exit(1)


if __name__ == "__main__":
    main()
