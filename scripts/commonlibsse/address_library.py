"""Skyrim SE / AE / VR address library database loader.

SE (1.5.97) and AE (1.6.1170) ship as compressed .bin files in the meh321
V1/V2 format.  VR (1.4.15) ships as a flat CSV with a metadata row.  All
three share the SE-derived ID namespace, so a single ID can be looked up
across all three DBs.
"""

from __future__ import annotations

import os
import struct
from typing import Dict


class AddressLibrary:
    """Loads address-library databases mapping relocation IDs to RVAs."""

    def __init__(self):
        self.se_db: Dict[int, int] = {}
        self.ae_db: Dict[int, int] = {}
        self.vr_db: Dict[int, int] = {}

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

    @staticmethod
    def load_csv(file_path: str, skip_meta: bool = True) -> Dict[int, int]:
        """Read an 'id,offset' CSV file (header + optional metadata row).

        The community VR address libraries (Old, etc.) ship as CSV rather
        than the meh321 binary format.  Format:

          id,offset                          # header line
          <metadata>,<game-version-string>   # one metadata row (skipped)
          <id>,<hex-offset>                  # entries

        ``offset`` is parsed as hex without a ``0x`` prefix.
        """
        if not os.path.exists(file_path):
            return {}
        db: Dict[int, int] = {}
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
        start = 2 if skip_meta and len(lines) > 1 else 1
        for line in lines[start:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split(',')
            if len(parts) != 2:
                continue
            try:
                db[int(parts[0])] = int(parts[1], 16)
            except ValueError:
                continue
        return db

    def load_all(self, base_path: str) -> None:
        sse_dir = os.path.join(base_path, 'sse')
        self.se_db = self.load_bin(os.path.join(sse_dir, 'version-1-5-97-0.bin'))
        self.ae_db = self.load_bin(os.path.join(sse_dir, 'versionlib-1-6-1170-0.bin'))
        self.vr_db = self.load_csv(os.path.join(sse_dir, 'version-1-4-15-0.csv'))
