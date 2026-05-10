"""Fallout 4 address library loader (libxse/commonlibf4 format).

Binary format (from CommonLibF4 IDDatabase::load()):
  uint64  count
  count x (uint64 id, uint64 offset) pairs, sorted by id

Loads OG (1.10.163), NG (1.10.984), AE (1.11.191), and VR (1.2.72).

OG and AE/NG IDs share the same meh321-maintained namespace: a single ID
resolves to a function's offset in whichever DBs it exists in.  VR uses a
disjoint community-maintained namespace and ships as a flat CSV.  Looking
up an AE-namespace ID against the VR DB only ever finds coincidental
low-ID matches that point at the wrong functions, so VR symbols are only
populated when CommonLibF4 explicitly references a VR ID.

CommonLibF4's headers carry NG/AE IDs (1.10.984 / 1.11.191), so symbol
resolution for OG/VR scripts comes from types and labels only; function
addresses must be reconstructed via a separate post-pass (e.g. byte-sig
porting from AE).
"""

from __future__ import annotations

import os
import struct
from typing import Dict, Optional


class F4AddressLibrary:
    """Loads Fallout 4 address library databases (OG / NG / AE / VR)."""

    def __init__(self):
        self.og_db: Dict[int, int] = {}
        self.ng_db: Dict[int, int] = {}
        self.ae_db: Dict[int, int] = {}
        self.vr_db: Dict[int, int] = {}

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

    @staticmethod
    def load_csv(file_path: str, skip_meta: bool = True) -> Dict[int, int]:
        """Read an 'id,offset' CSV file (header + optional metadata row).

        The community VR address library ships as CSV rather than the
        meh321 binary format.  Format:

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
        self.og_db = self.load_bin(os.path.join(base_path, 'version-1-10-163-0.bin'))
        # NG ships as two patch revisions (1.10.980 then 1.10.984) with mostly
        # identical address layouts; users may have either binary, so prefer
        # the newer one when both are present and fall back to whichever ships.
        ng_984 = os.path.join(base_path, 'version-1-10-984-0.bin')
        ng_980 = os.path.join(base_path, 'version-1-10-980-0.bin')
        ng_path = ng_984 if os.path.exists(ng_984) else ng_980
        self.ng_db = self.load_bin(ng_path)
        self.ae_db = self.load_bin(os.path.join(base_path, 'version-1-11-191-0.bin'))
        self.vr_db = self.load_csv(os.path.join(base_path, 'version-1-2-72-0.csv'))

    def get_ae(self, id_: int) -> Optional[int]:
        return self.ae_db.get(id_) if id_ else None
