"""PE executable version detection."""

from __future__ import annotations

import struct
from typing import Optional, Tuple


def get_pe_version(exe_path: str) -> Optional[Tuple[int, ...]]:
    """Extract the file version from a PE executable.

    Tries VS_FIXEDFILEINFO binary fields first, then falls back to the
    FileVersion string table entry. Returns a version tuple or None.
    """
    try:
        with open(exe_path, 'rb') as f:
            data = f.read()
    except OSError:
        return None

    # Try VS_FIXEDFILEINFO binary fields
    sig = b'\xbd\x04\xef\xfe'
    pos = data.find(sig)
    if pos >= 0 and pos + 16 <= len(data):
        try:
            ms = struct.unpack_from('<I', data, pos + 8)[0]
            ls = struct.unpack_from('<I', data, pos + 12)[0]
            ver = (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
            if ver[0] > 0 and ver != (1, 0, 0, 0):
                return ver
        except struct.error:
            pass

    # Fallback: parse FileVersion string from the version resource (UTF-16LE)
    needle = 'FileVersion'.encode('utf-16-le')
    spos = data.find(needle)
    if spos >= 0:
        key_end = spos + len(needle) + 2
        aligned = (key_end + 3) & ~3
        raw = data[aligned:aligned + 64]
        try:
            val = raw.decode('utf-16-le', errors='replace').split('\x00')[0].strip()
            parts = [int(x) for x in val.split('.')]
            if len(parts) >= 3 and parts[0] > 0:
                return tuple(parts)
        except (ValueError, IndexError):
            pass

    return None
