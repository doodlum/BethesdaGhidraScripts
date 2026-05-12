#!/usr/bin/env python3
"""
One-click setup and run.

Drop game executables under exes/<game>/<version>/ and run this script:

  exes/skyrim/se/SkyrimSE.exe
  exes/skyrim/ae/SkyrimSE.exe
  exes/f4/ae/Fallout4.exe

Everything else is handled automatically. On subsequent runs, expensive steps
(script generation, headless import) are skipped unless something has actually
changed (submodule update, new/replaced exe, missing project).
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
    # Used by scripts/commonlibf4/run_bytesig_port.py for the masked-retry
    # pass that wildcards rel32 / rip-rel operands on cross-build matches
    # (AE -> OG / VR).  Without them the byte-sig port still works for
    # exact 32-byte matches; masked Pass 2 is skipped with a notice.
    "capstone": "capstone",
    "numpy":    "numpy",
}

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


# -- State tracking ----------------------------------------------------

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


def _project_exists():
    gpr = PROJECTS_DIR / GHIDRA_PROJECT_NAME / f"{GHIDRA_PROJECT_NAME}.gpr"
    return gpr.is_file()


def _scripts_exist(games):
    if "skyrim" in games:
        for name in ("CommonLibImport_SE.py", "CommonLibImport_AE.py"):
            if not (GHIDRA_SCRIPTS_DIR / name).is_file():
                return False
    if "f4" in games:
        if not (GHIDRA_SCRIPTS_DIR / "CommonLibImport_F4_AE.py").is_file():
            return False
    return True


# -- Prerequisites -----------------------------------------------------

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


def _clang_version():
    try:
        r = subprocess.run(
            ["clang", "--version"], capture_output=True, text=True, check=True)
        return r.stdout.strip().splitlines()[0]
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


# -- LLVM / Clang ------------------------------------------------------

def _ensure_clang():
    """Make sure clang is available; download LLVM locally if not."""
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

    # Migrate from old location (repo root) to tools/
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
        # F4 OG and VR use disjoint ID namespaces from NG/AE — CommonLibF4
        # IDs don't resolve there.  If AE (or NG) and OG/VR binaries are
        # both present, port AE-known function names across via masked
        # byte-signature matching so OG/VR scripts apply function names
        # instead of types-only.
        print("  Fallout 4 cross-version byte-signature port ...")
        subprocess.run(
            [sys.executable,
             str(SCRIPTS_DIR / "commonlibf4" / "run_bytesig_port.py")],
            cwd=str(REPO_DIR), check=False)


# -- Headless ----------------------------------------------------------

def run_headless():
    _header("Headless Ghidra Import")
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "run_headless.py")],
        cwd=str(REPO_DIR)).returncode


# -- Launch Ghidra -----------------------------------------------------

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

    # Remove stale lock left by headless run (JPype/JVM may not release instantly)
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
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
    else:
        subprocess.Popen(
            [str(launcher), str(gpr)],
            cwd=str(GHIDRA_DIR),
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)


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

    prev = _load_state()
    cur_subs = _get_submodule_hashes()
    cur_exes = _get_exe_fingerprints()

    subs_changed    = cur_subs != prev.get("submodules")
    exes_changed    = cur_exes != prev.get("exes")
    project_missing = not _project_exists()
    scripts_missing = not _scripts_exist(games)

    need_generate = subs_changed or scripts_missing
    need_import   = need_generate or exes_changed or project_missing

    rc = 0

    if need_generate:
        generate_scripts(games)
    else:
        print("\n  Import scripts up to date, skipping generation.")

    if need_import:
        rc = run_headless()
    else:
        print("  Ghidra project up to date, skipping import.")

    if rc == 0:
        _save_state(cur_subs, cur_exes)

    launch_ghidra()

    print("\n" + "=" * 60)
    if rc == 0:
        print("  Done!")
    else:
        print("  Finished with errors (see above)")
    print("=" * 60)
    sys.exit(rc)


if __name__ == "__main__":
    main()
