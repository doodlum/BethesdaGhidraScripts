"""Per-binary vtable layout data model + CSV I/O.

A vtable layout is "the actual slot-by-slot contents of a class's vtable in a
specific binary build" -- ground truth, extracted from the binary itself.
Distinct from CommonLib's *header-described* layout, which assumes a single
canonical version and silently breaks for patches that re-shuffle slots
(Skyrim VR +2, F4 NG/AE/VR all drift in different ways).

CSV format (one file per binary, one row per slot):

    class,vtable_addr,slot,func_addr,func_name,fingerprint
    PlayerCharacter,0x1416635e0,0,0x140f58870,PlayerCharacter::~PlayerCharacter,488B...
    PlayerCharacter,0x1416635e0,1,0x140049ab0,Actor::InitializeData,488B...
    Actor,0x141662a40,0,0x140f4d000,Actor::~Actor,488B...
    ...

- `slot` is decimal slot index (not hex, not byte offset).
- `func_name` may be empty when the binary's PDB doesn't name the function;
  the matcher uses `fingerprint` to align such slots across versions.
- `fingerprint` is a Ghidra-style masked byte pattern (hex bytes separated
  by spaces, `?` for unknown / relocation-masked bytes).  First ~32 bytes
  is usually enough for unique cross-version matching of vfunc bodies.
"""
from __future__ import annotations

import csv
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class SlotEntry:
    """One slot's contents in a class's vtable, as observed in a binary."""
    slot: int           # 0-based slot index
    func_addr: int      # function pointer stored at this slot
    func_name: str      # PDB / Ghidra-resolved name, or '' if unknown
    fingerprint: str    # masked byte pattern of the pointed-to function

    @property
    def slot_hex(self) -> str:
        return '0x{:X}'.format(self.slot)

    @property
    def byte_offset(self) -> int:
        return self.slot * 8


@dataclass
class ClassVtable:
    """All slots of one class's primary vtable in one binary."""
    class_name: str
    vtable_addr: int
    slots: Dict[int, SlotEntry] = field(default_factory=dict)

    def add(self, entry: SlotEntry) -> None:
        self.slots[entry.slot] = entry

    def slot(self, idx: int) -> Optional[SlotEntry]:
        return self.slots.get(idx)

    @property
    def max_slot(self) -> int:
        return max(self.slots.keys()) if self.slots else -1


@dataclass
class BinaryLayout:
    """All extracted class vtables for one binary."""
    binary_label: str                              # 'f4_ng', 'svr', etc
    binary_path: str = ''                          # informational
    classes: Dict[str, ClassVtable] = field(default_factory=dict)

    def get(self, class_name: str) -> Optional[ClassVtable]:
        return self.classes.get(class_name)

    def upsert(self, class_name: str, vtable_addr: int) -> ClassVtable:
        cv = self.classes.get(class_name)
        if cv is None:
            cv = ClassVtable(class_name=class_name, vtable_addr=vtable_addr)
            self.classes[class_name] = cv
        return cv


def _parse_hex_or_dec(s: str) -> int:
    s = (s or '').strip()
    if not s:
        raise ValueError('empty numeric field')
    return int(s, 16) if s.lower().startswith('0x') else int(s)


def load_csv(path: str, binary_label: str) -> BinaryLayout:
    """Load a per-binary vtable layout CSV.  Missing file -> empty layout."""
    layout = BinaryLayout(binary_label=binary_label, binary_path=path)
    if not os.path.isfile(path):
        return layout
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cls = (row.get('class') or '').strip()
            if not cls:
                continue
            try:
                vt_addr = _parse_hex_or_dec(row.get('vtable_addr', '0'))
                slot = _parse_hex_or_dec(row.get('slot', ''))
                func_addr = _parse_hex_or_dec(row.get('func_addr', '0'))
            except ValueError:
                continue
            cv = layout.upsert(cls, vt_addr)
            cv.add(SlotEntry(
                slot=slot,
                func_addr=func_addr,
                func_name=(row.get('func_name') or '').strip(),
                fingerprint=(row.get('fingerprint') or '').strip(),
            ))
    return layout


def save_csv(layout: BinaryLayout, path: str) -> int:
    """Write a per-binary layout to CSV.  Returns row count."""
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    rows = 0
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['class', 'vtable_addr', 'slot', 'func_addr', 'func_name', 'fingerprint'])
        for cls_name in sorted(layout.classes):
            cv = layout.classes[cls_name]
            for slot in sorted(cv.slots):
                e = cv.slots[slot]
                writer.writerow([
                    cls_name,
                    '0x{:X}'.format(cv.vtable_addr),
                    e.slot,
                    '0x{:X}'.format(e.func_addr),
                    e.func_name,
                    e.fingerprint,
                ])
                rows += 1
    return rows
