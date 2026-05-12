"""Shared Steamless wrapper.

Detect and strip SteamStub DRM via the Steamless CLI.  Returns an unpacked
copy when DRM was present, otherwise the original binary.  A previously
unpacked file newer than the source is reused without re-running Steamless.
On non-Windows hosts or when the CLI is missing, this is a transparent
no-op that returns the original binary.

Used by:
  - scripts/run_headless.py            (before Ghidra import)
  - scripts/commonlibf4/run_bytesig_port.py  (before reading PE bytes)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def ensure_unpacked(binary: Path, steamless_cli: Path) -> Path:
    if not steamless_cli.is_file() or sys.platform != "win32":
        return binary

    src_mtime = binary.stat().st_mtime
    src_size  = binary.stat().st_size

    def find_unpacked():
        # Steamless versions vary: <stem>.unpacked.exe or <name>.unpacked[.exe]
        for c in binary.parent.glob(f"{binary.stem}*unpacked*"):
            if c == binary or not c.is_file():
                continue
            cstat = c.stat()
            if cstat.st_mtime >= src_mtime and cstat.st_size >= src_size // 2:
                return c
        return None

    cached = find_unpacked()
    if cached is not None:
        print(f"Using cached Steamless output: {cached.name}")
        return cached

    print(f"Running Steamless on {binary.name} ...")
    try:
        result = subprocess.run(
            [str(steamless_cli), "--quiet", "--keepbind", str(binary)],
            capture_output=True, text=True, check=False,
            cwd=str(steamless_cli.parent),
        )
        if result.stdout.strip(): print(result.stdout.rstrip())
        if result.stderr.strip(): print(result.stderr.rstrip(), file=sys.stderr)
    except Exception as e:
        print(f"  Steamless failed to run: {e} -- using original binary.")
        return binary

    out = find_unpacked()
    if out is not None:
        print(f"  SteamStub DRM removed -> {out.name}")
        return out
    print("  No SteamStub DRM detected; using original binary.")
    return binary
