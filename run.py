#!/usr/bin/env python3
"""
One-click setup and run.

Drop game executables under exes/<game>/<version>/ and run this script:

  exes/skyrim/se/SkyrimSE.exe
  exes/skyrim/ae/SkyrimSE.exe
  exes/f4/ae/Fallout4.exe

Everything else is handled automatically:
  - Git submodules updated to latest upstream
  - Python dependencies installed
  - Ghidra downloaded and extracted (if missing)
  - Steamless downloaded for DRM removal (Windows, if missing)
  - CommonLib import scripts generated via clang
  - Headless Ghidra import and verification
"""
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

REPO_DIR      = Path(__file__).resolve().parent
GHIDRA_DIR    = REPO_DIR / "ghidra"
EXES_ROOT     = REPO_DIR / "exes"
SCRIPTS_DIR   = REPO_DIR / "scripts"
STEAMLESS_DIR = REPO_DIR / "tools" / "Steamless"

GHIDRA_RELEASES_URL    = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
STEAMLESS_RELEASES_URL = "https://api.github.com/repos/atom0s/Steamless/releases/latest"

REQUIRED_PACKAGES = {"pdbparse": "pdbparse", "pyghidra": "pyghidra"}

API_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "BethesdaGhidraScripts",
}


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


# -- Prerequisites ----------------------------------------------------

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


def _can_import(name):
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def _check_clang():
    try:
        r = subprocess.run(
            ["clang", "--version"], capture_output=True, text=True, check=True)
        print(f"  {r.stdout.strip().splitlines()[0]}")
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


# -- Submodules --------------------------------------------------------

def update_submodules():
    _header("Submodules")
    subprocess.run(
        ["git", "submodule", "update", "--init", "--recursive", "--remote"],
        cwd=str(REPO_DIR), check=True)
    print("  Up to date.")


# -- Ghidra -----------------------------------------------------------

def _ghidra_version(path):
    props = path / "Ghidra" / "application.properties"
    if props.is_file():
        for line in props.read_text().splitlines():
            if line.startswith("application.version="):
                return line.split("=", 1)[1]
    return None


def setup_ghidra():
    _header("Ghidra")

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
            if GHIDRA_DIR.exists():
                shutil.rmtree(GHIDRA_DIR)
            shutil.copytree(str(src), str(GHIDRA_DIR))
    finally:
        tmp_path.unlink(missing_ok=True)

    ver = _ghidra_version(GHIDRA_DIR)
    print(f"  Ghidra {ver or '?'} installed")


# -- Steamless ---------------------------------------------------------

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


# -- Discovery ---------------------------------------------------------

def discover_games():
    games = set()
    if not EXES_ROOT.is_dir():
        return games
    for game_dir in EXES_ROOT.iterdir():
        if not game_dir.is_dir():
            continue
        for ver_dir in game_dir.iterdir():
            if ver_dir.is_dir() and any(ver_dir.glob("*.exe")):
                games.add(game_dir.name)
    return games


# -- Generation --------------------------------------------------------

def generate_scripts(games):
    _header("Generating Import Scripts")

    if not _check_clang():
        print("  ERROR: clang not found on PATH -- install LLVM/Clang")
        sys.exit(1)

    if "skyrim" in games:
        print("  Skyrim SE / AE ...")
        subprocess.run(
            [sys.executable,
             str(SCRIPTS_DIR / "commonlibsse" / "parse_commonlib_types.py")],
            cwd=str(REPO_DIR), check=True)
    if "f4" in games:
        print("  Fallout 4 AE ...")
        subprocess.run(
            [sys.executable,
             str(SCRIPTS_DIR / "commonlibf4" / "parse_commonlib_types.py")],
            cwd=str(REPO_DIR), check=True)


# -- Headless ----------------------------------------------------------

def run_headless():
    _header("Headless Ghidra Import")
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "run_headless.py")],
        cwd=str(REPO_DIR)).returncode


# -- Main --------------------------------------------------------------

def main():
    print("=" * 60)
    print("  Bethesda Ghidra Scripts")
    print("=" * 60)

    check_prerequisites()
    update_submodules()
    setup_ghidra()
    setup_steamless()

    games = discover_games()
    if not games:
        _header("No Executables Found")
        print("  Place game .exe files under exes/<game>/<version>/:")
        print()
        print("    exes/skyrim/se/SkyrimSE.exe")
        print("    exes/skyrim/ae/SkyrimSE.exe")
        print("    exes/f4/ae/Fallout4.exe")
        sys.exit(1)

    print(f"\n  Detected: {', '.join(sorted(games))}")

    generate_scripts(games)
    rc = run_headless()

    print("\n" + "=" * 60)
    if rc == 0:
        print("  Done!")
    else:
        print("  Finished with errors (see above)")
    print("=" * 60)
    sys.exit(rc)


if __name__ == "__main__":
    main()
