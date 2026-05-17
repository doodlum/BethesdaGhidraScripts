"""Starfield address library database loader.

Single-version (1.16.236.0 at the time of writing): the canonical
meh321-format binary that the community ships under
``SFSE/Plugins/versionlib-1-16-236-0.bin``.  Format is identical to the SSE
and F4 .bin layouts -- only the path differs.
"""

from __future__ import annotations

import os
import struct
from typing import Dict


class AddressLibrary:
    """Loads the Starfield address-library database mapping IDs to RVAs."""

    def __init__(self):
        self.sf_db: Dict[int, int] = {}

    def load_bin(self, file_path: str) -> Dict[int, int]:
        """Read a Starfield versionlib .bin file.

        Starfield uses meh321's database format V5, which is much simpler
        than the V1/V2 delta-encoded format that SSE/F4 use::

          fmt          u32          (== 5)
          version[4]   4 x u32
          name         char[64]     zero-padded
          ptr_size     u64
          addr_count   u32
          entries      u32[addr_count]   indexed by id, value = rva

        Zero-valued entries are treated as "no mapping" and skipped.  V1/V2
        binaries are also accepted for forward compatibility.
        """
        if not os.path.exists(file_path):
            return {}
        with open(file_path, 'rb') as f:
            data = f.read()
        return self._parse_bytes(data)

    @staticmethod
    def _parse_bytes(data: bytes) -> Dict[int, int]:
        db: Dict[int, int] = {}
        fmt = struct.unpack_from('<I', data, 0)[0]
        if fmt == 5:
            # Header: 4 (fmt) + 16 (version) + 64 (name) + 8 (ptr_size) + 4 (addr_count) = 96 bytes
            addr_count = struct.unpack_from('<I', data, 92)[0]
            entries_off = 96
            for i in range(addr_count):
                off = struct.unpack_from('<I', data, entries_off + i * 4)[0]
                if off:
                    db[i] = off
            return db

        # V1 / V2 fallback (delta encoding).
        import io
        f = io.BytesIO(data)
        f.read(4)                                              # fmt
        f.read(16)                                             # version
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

    def load_all(self, base_path: str, version: str = '1-16-236-0') -> None:
        sf_dir = os.path.join(base_path, 'starfield')
        self.sf_db = self.load_bin(os.path.join(sf_dir, f'versionlib-{version}.bin'))
