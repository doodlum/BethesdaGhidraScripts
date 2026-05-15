"""Skyrim SE/AE address library database loader.

Supports two binary formats:
  - Per-version .bin files (delta-encoded, from Address Library for SKSE)
  - Multi-version .relib files (flat, from AddressLibraryDatabase)

When loading, the .relib is used to find mappings for any AE version
without requiring per-version .bin files to be pre-generated.
"""

from __future__ import annotations

import glob
import os
import struct
import sys
from typing import Dict, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
from pe_version import get_pe_version  # noqa: E402


def _read_dotnet_string(f) -> str:
    """Read a .NET BinaryWriter-style length-prefixed string."""
    length = 0
    shift = 0
    while True:
        b = struct.unpack('<B', f.read(1))[0]
        length |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            break
    return f.read(length).decode('utf-8')


def load_relib_version(relib_path: str, target_version: Tuple[int, ...]) -> Dict[int, int]:
    """Load ID-to-RVA mappings for a specific version from a .relib file.

    Returns an empty dict if the version is not found in the database.
    """
    if not os.path.exists(relib_path):
        return {}

    target_tuple = tuple(target_version)

    with open(relib_path, 'rb') as f:
        fmt_version = struct.unpack('<i', f.read(4))[0]
        _high_vid = struct.unpack('<Q', f.read(8))[0]
        _ptr_size = struct.unpack('<i', f.read(4))[0]

        has_module = struct.unpack('<B', f.read(1))[0]
        if has_module:
            _read_dotnet_string(f)

        num_versions = struct.unpack('<i', f.read(4))[0]

        for _ in range(num_versions):
            n_components = struct.unpack('<i', f.read(4))[0]
            ver = tuple(struct.unpack('<I', f.read(4))[0] for _ in range(n_components))

            has_overwrite = struct.unpack('<B', f.read(1))[0]
            if has_overwrite:
                _read_dotnet_string(f)

            _base_addr = struct.unpack('<q', f.read(8))[0]
            value_count = struct.unpack('<i', f.read(4))[0]

            if ver == target_tuple:
                db = {}
                for _ in range(value_count):
                    k = struct.unpack('<Q', f.read(8))[0]
                    v = struct.unpack('<I', f.read(4))[0]
                    db[k] = v
                return db

            # Skip values for non-matching versions
            f.seek(value_count * 12, 1)

            if fmt_version >= 2:
                hash_count = struct.unpack('<i', f.read(4))[0]
                f.seek(hash_count * 16, 1)

    return {}


def list_relib_versions(relib_path: str) -> list:
    """List all versions available in a .relib file."""
    if not os.path.exists(relib_path):
        return []

    versions = []
    with open(relib_path, 'rb') as f:
        fmt_version = struct.unpack('<i', f.read(4))[0]
        _high_vid = struct.unpack('<Q', f.read(8))[0]
        _ptr_size = struct.unpack('<i', f.read(4))[0]

        has_module = struct.unpack('<B', f.read(1))[0]
        if has_module:
            _read_dotnet_string(f)

        num_versions = struct.unpack('<i', f.read(4))[0]

        for _ in range(num_versions):
            n_components = struct.unpack('<i', f.read(4))[0]
            ver = tuple(struct.unpack('<I', f.read(4))[0] for _ in range(n_components))
            versions.append(ver)

            has_overwrite = struct.unpack('<B', f.read(1))[0]
            if has_overwrite:
                _read_dotnet_string(f)

            _base_addr = struct.unpack('<q', f.read(8))[0]
            value_count = struct.unpack('<i', f.read(4))[0]
            f.seek(value_count * 12, 1)

            if fmt_version >= 2:
                hash_count = struct.unpack('<i', f.read(4))[0]
                f.seek(hash_count * 16, 1)

    return versions


class AddressLibrary:
    """Loads address-library binary databases mapping relocation IDs to RVAs."""

    def __init__(self):
        self.se_db: Dict[int, int] = {}
        self.ae_db: Dict[int, int] = {}

    def load_bin(self, file_path: str) -> Dict[int, int]:
        if not os.path.exists(file_path):
            return {}
        db = {}
        with open(file_path, 'rb') as f:
            f.read(4)   # fmt
            f.read(16)  # version
            name_len = struct.unpack('<I', f.read(4))[0]
            f.read(name_len)
            ptr_size   = struct.unpack('<I', f.read(4))[0]
            addr_count = struct.unpack('<I', f.read(4))[0]
            pvid = 0; poffset = 0
            for _ in range(addr_count):
                type_byte = struct.unpack('<B', f.read(1))[0]
                low = type_byte & 0xF; high = type_byte >> 4
                if   low == 0: id_val = struct.unpack('<Q', f.read(8))[0]
                elif low == 1: id_val = pvid + 1
                elif low == 2: id_val = pvid + struct.unpack('<B', f.read(1))[0]
                elif low == 3: id_val = pvid - struct.unpack('<B', f.read(1))[0]
                elif low == 4: id_val = pvid + struct.unpack('<H', f.read(2))[0]
                elif low == 5: id_val = pvid - struct.unpack('<H', f.read(2))[0]
                elif low == 6: id_val = struct.unpack('<H', f.read(2))[0]
                elif low == 7: id_val = struct.unpack('<I', f.read(4))[0]
                tpoffset = (poffset // ptr_size) if (high & 8) != 0 else poffset
                h_type = high & 7
                if   h_type == 0: off_val = struct.unpack('<Q', f.read(8))[0]
                elif h_type == 1: off_val = tpoffset + 1
                elif h_type == 2: off_val = tpoffset + struct.unpack('<B', f.read(1))[0]
                elif h_type == 3: off_val = tpoffset - struct.unpack('<B', f.read(1))[0]
                elif h_type == 4: off_val = tpoffset + struct.unpack('<H', f.read(2))[0]
                elif h_type == 5: off_val = tpoffset - struct.unpack('<H', f.read(2))[0]
                elif h_type == 6: off_val = struct.unpack('<H', f.read(2))[0]
                elif h_type == 7: off_val = struct.unpack('<I', f.read(4))[0]
                if (high & 8) != 0: off_val *= ptr_size
                db[id_val] = off_val; pvid = id_val; poffset = off_val
        return db

    def _find_bin(self, directory: str, version: Tuple[int, ...], prefix: str) -> Optional[str]:
        """Find a per-version .bin file matching the given version tuple."""
        ver_str = '-'.join(str(v) for v in version)
        exact = os.path.join(directory, '{}-{}.bin'.format(prefix, ver_str))
        if os.path.isfile(exact):
            return exact
        for f in glob.glob(os.path.join(directory, '{}*.bin'.format(prefix))):
            try:
                with open(f, 'rb') as fh:
                    fh.read(4)  # fmt
                    v = struct.unpack('<IIII', fh.read(16))
                    if v == tuple(version):
                        return f
            except (OSError, struct.error):
                continue
        return None

    def load_all(self, base_path: str,
                 se_version: Optional[Tuple[int, ...]] = None,
                 ae_version: Optional[Tuple[int, ...]] = None) -> None:
        """Load SE and AE address databases.

        If version tuples are provided, searches for matching .bin files first,
        then falls back to the .relib database from AddressLibraryDatabase.
        If no version is given, falls back to the legacy hardcoded filenames.
        """
        sse_dir = os.path.join(base_path, 'sse')
        relib_path = os.path.join(os.path.dirname(base_path),
                                  'extern', 'AddressLibraryDatabase', 'skyrimae.relib')

        # SE database
        se_default = os.path.join(sse_dir, 'version-1-5-97-0.bin')
        if se_version:
            bin_path = self._find_bin(sse_dir, se_version, 'version')
            if bin_path:
                print('  SE address library: {} (version {})'.format(
                    os.path.basename(bin_path), '.'.join(str(v) for v in se_version)))
                self.se_db = self.load_bin(bin_path)
            elif os.path.isfile(se_default):
                print('  SE address library: version-1-5-97-0.bin (fallback)')
                self.se_db = self.load_bin(se_default)
            else:
                print('  WARNING: no SE address library for version {}'.format(
                    '.'.join(str(v) for v in se_version)))
                self.se_db = {}
        else:
            self.se_db = self.load_bin(se_default)
            if self.se_db:
                print('  SE address library: version-1-5-97-0.bin (default)')

        # AE database
        if ae_version:
            bin_path = self._find_bin(sse_dir, ae_version, 'versionlib')
            if bin_path:
                print('  AE address library: {} (version {})'.format(
                    os.path.basename(bin_path), '.'.join(str(v) for v in ae_version)))
                self.ae_db = self.load_bin(bin_path)
            elif os.path.isfile(relib_path):
                ver_str = '.'.join(str(v) for v in ae_version)
                print('  AE address library: skyrimae.relib (version {})'.format(ver_str))
                self.ae_db = load_relib_version(relib_path, ae_version)
                if not self.ae_db:
                    available = list_relib_versions(relib_path)
                    avail_str = ', '.join('.'.join(str(v) for v in ver) for ver in available)
                    print('  WARNING: version {} not found in relib'.format(ver_str))
                    print('  Available versions: {}'.format(avail_str))
            else:
                print('  WARNING: no AE address library for version {}'.format(
                    '.'.join(str(v) for v in ae_version)))
                self.ae_db = {}
        else:
            self.ae_db = self.load_bin(os.path.join(sse_dir, 'versionlib-1-6-1170-0.bin'))
            if self.ae_db:
                print('  AE address library: versionlib-1-6-1170-0.bin (default)')
