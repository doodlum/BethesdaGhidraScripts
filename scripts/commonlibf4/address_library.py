"""Fallout 4 address library loader (libxse/commonlibf4 format).

Binary format (from CommonLibF4 IDDatabase::load()):
  uint64  count
  count x (uint64 id, uint64 offset) pairs, sorted by id
"""

from __future__ import annotations

import glob
import os
import struct
import sys
from typing import Dict, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
from pe_version import get_pe_version  # noqa: E402


class F4AddressLibrary:
    """Loads the Fallout 4 address library .bin file."""

    def __init__(self):
        self.ae_db: Dict[int, int] = {}

    def load_bin(self, file_path: str) -> Dict[int, int]:
        if not os.path.exists(file_path):
            return {}
        db = {}
        with open(file_path, 'rb') as f:
            count = struct.unpack('<Q', f.read(8))[0]
            for _ in range(count):
                id_, offset = struct.unpack('<QQ', f.read(16))
                db[id_] = offset
        return db

    def load_all(self, base_path: str,
                 ae_version: Optional[Tuple[int, ...]] = None) -> None:
        default = os.path.join(base_path, 'version-1-11-191-0.bin')

        if ae_version:
            ver_str = '-'.join(str(v) for v in ae_version)
            exact = os.path.join(base_path, 'version-{}.bin'.format(ver_str))
            if os.path.isfile(exact):
                print('  F4 address library: {} (version {})'.format(
                    os.path.basename(exact), '.'.join(str(v) for v in ae_version)))
                self.ae_db = self.load_bin(exact)
                return
            for f in sorted(glob.glob(os.path.join(base_path, 'version-*.bin'))):
                if os.path.isfile(f):
                    print('  F4 address library: {} (fallback)'.format(os.path.basename(f)))
                    self.ae_db = self.load_bin(f)
                    return

        self.ae_db = self.load_bin(default)
        if self.ae_db:
            print('  F4 address library: version-1-11-191-0.bin (default)')

    def get_ae(self, id_: int) -> Optional[int]:
        return self.ae_db.get(id_) if id_ else None
