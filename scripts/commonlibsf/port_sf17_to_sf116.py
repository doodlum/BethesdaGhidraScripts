#!/usr/bin/env python3
"""Phase 2 of SF 1.7 -> SF 1.16.236 byte-sig naming port.

Inputs:
  - Source XML + .bytes (Ghidra export of user's analyzed Starfield 1.7).
  - Target PE: C:/Games/Starfield 1.16.236/Starfield.exe.

Output:
  - scripts/commonlibsf/refs/sf116_ported_names.csv with columns
    target_rva,name,pass (pass = "exact32" or "masked48").

Pipeline:
  1. Parse source XML MEMORY_SECTION elements to find .text RVA/length/
     FILE_OFFSET in the .bytes file.
  2. Stream the source XML for FUNCTION entries; filter noise (FUN_*,
     thunk_*, _dynamic_initializer*, _lambda_*).
  3. Load target .text via bytesig_port.load_pe_text + build_prefix_index.
  4. Pass 1: port with exact 32-byte match.
  5. Pass 2: re-port the misses with masked 48-byte match (wildcards
     rel32/rip-rel operands).
  6. Emit ported CSV.

Phase 3 (apply names to 1.16.236 Ghidra DB) is separate.
"""
from __future__ import annotations

import csv
import io
import os
import re
import sys
import time
from html import unescape

_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(os.path.dirname(_SCRIPT_DIR))
sys.path.insert(0, os.path.join(_PROJECT_DIR, "scripts", "core"))

from bytesig_port import (  # noqa: E402
    load_pe_text, build_prefix_index, port_symbols,
)

SRC_XML    = r"C:/Users/Noud/Starfield.exe.xml"
SRC_BYTES  = r"C:/Users/Noud/Starfield.exe.bytes"
TGT_PE     = r"C:/Games/Starfield 1.16.236/Starfield.exe"
OUT_CSV    = os.path.join(_SCRIPT_DIR, "refs", "sf116_ported_names.csv")

NOISE_PREFIXES = ("FUN_", "thunk_FUN_", "sub_")
NOISE_SUBSTRINGS = (
    "_dynamic_initializer_for_",
    "_lambda_",
    "API-MS-",
)


def is_noise(name: str) -> bool:
    return (any(name.startswith(p) for p in NOISE_PREFIXES)
            or any(s in name for s in NOISE_SUBSTRINGS))


MEMSEC_RE = re.compile(
    r'<MEMORY_SECTION\s+NAME="(?P<name>[^"]+)"\s+'
    r'START_ADDR="(?P<start>[0-9a-fA-F]+)"\s+'
    r'LENGTH="(?P<length>0x[0-9a-fA-F]+|\d+)"'
)
MEMCONT_RE = re.compile(
    r'<MEMORY_CONTENTS\s+FILE_NAME="(?P<file>[^"]+)"\s+'
    r'FILE_OFFSET="(?P<off>0x[0-9a-fA-F]+|\d+)"'
)
FUNCTION_RE = re.compile(
    r'<FUNCTION\s+ENTRY_POINT="(?P<rva>[0-9a-fA-F]+)"\s+NAME="(?P<name>[^"]+)"'
)


def _int(s: str) -> int:
    """Ghidra XML always uses hex addresses, sometimes 0x-prefixed and
    sometimes bare (e.g. START_ADDR="140001000").  Bare decimal is never
    used for addresses in this format.
    """
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 16)


def parse_text_section(xml_path: str):
    """Return (text_start_va, text_length, text_file_offset).

    First .text MEMORY_SECTION that has a MEMORY_CONTENTS file-offset
    pointer wins (some XMLs have additional uninitialized .text segments
    without backing bytes -- we don't care about those).
    """
    with open(xml_path, "rb") as fh:
        pending = None
        for raw in fh:
            try:
                line = raw.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                continue
            m = MEMSEC_RE.search(line)
            if m and m.group("name") == ".text":
                pending = (_int(m.group("start")), _int(m.group("length")))
                continue
            if pending is not None:
                mc = MEMCONT_RE.search(line)
                if mc:
                    return pending[0], pending[1], _int(mc.group("off"))
                # MEMORY_SECTION without a MEMORY_CONTENTS child means
                # an uninitialized section -- skip it and keep scanning.
                if line.lstrip().startswith("<MEMORY_SECTION"):
                    pending = None
    raise RuntimeError("no .text MEMORY_SECTION with FILE_OFFSET found in XML")


def stream_function_entries(xml_path: str):
    """Yield (rva, name) for non-noise FUNCTION elements."""
    with open(xml_path, "rb") as fh:
        for raw in fh:
            try:
                line = raw.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                continue
            m = FUNCTION_RE.search(line)
            if not m:
                continue
            name = unescape(m.group("name"))
            if is_noise(name):
                continue
            yield _int(m.group("rva")), name


def main():
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    print(f"SRC_XML   = {SRC_XML}")
    print(f"SRC_BYTES = {SRC_BYTES}")
    print(f"TGT_PE    = {TGT_PE}")
    print(f"OUT_CSV   = {OUT_CSV}")
    if not (os.path.isfile(SRC_XML) and os.path.isfile(SRC_BYTES) and os.path.isfile(TGT_PE)):
        print("ERROR: one or more input files missing")
        sys.exit(2)
    print()

    # 1. Parse source .text mapping
    t0 = time.time()
    print("Parsing source .text MEMORY_SECTION header...")
    src_text_va, src_text_len, src_text_file_off = parse_text_section(SRC_XML)
    print(f"  .text VA          = 0x{src_text_va:x}")
    print(f"  .text length      = 0x{src_text_len:x}  ({src_text_len/1024/1024:.1f} MB)")
    print(f"  .text file offset = 0x{src_text_file_off:x}")
    print(f"  parsed in {time.time()-t0:.1f}s")

    # 2. Load source .text bytes
    print("Loading source .text bytes...")
    with open(SRC_BYTES, "rb") as fh:
        fh.seek(src_text_file_off)
        src_text = fh.read(src_text_len)
    if len(src_text) != src_text_len:
        print(f"  WARN: read {len(src_text)} bytes, expected {src_text_len}")
    # Assume source image base 0x140000000 (Bethesda standard).  RVA = VA - image_base.
    SRC_IMAGE_BASE = 0x140000000
    src_text_rva = src_text_va - SRC_IMAGE_BASE
    print(f"  src_text_rva = 0x{src_text_rva:x} ({len(src_text)} bytes loaded)")

    # 3. Stream-parse FUNCTION entries
    print("Streaming source FUNCTION entries...")
    t1 = time.time()
    src_named = []
    n_total = 0
    n_noise = 0
    for rva_va, name in stream_function_entries(SRC_XML):
        n_total += 1
        # FUNCTION ENTRY_POINT is a full VA, not an RVA -- convert
        rva = rva_va - SRC_IMAGE_BASE
        src_named.append((name, rva))
    print(f"  {n_total} named (post-filter) functions")
    print(f"  parsed in {time.time()-t1:.1f}s")

    # 4. Load target .text
    print(f"\nLoading target .text from PE: {TGT_PE}")
    tgt_image_base, tgt_text_rva, tgt_text = load_pe_text(TGT_PE)
    print(f"  tgt image_base = 0x{tgt_image_base:x}")
    print(f"  tgt .text rva  = 0x{tgt_text_rva:x}")
    print(f"  tgt .text size = 0x{len(tgt_text):x}  ({len(tgt_text)/1024/1024:.1f} MB)")

    # 5. Build prefix index for target
    print("Building target prefix index (k=6)...")
    t2 = time.time()
    tgt_idx = build_prefix_index(tgt_text, k=6)
    print(f"  {len(tgt_idx)} unique 6-byte prefixes  ({time.time()-t2:.1f}s)")

    # 6. Pass 1: exact 32-byte match
    print("\n=== Pass 1: exact 32-byte match ===")
    t3 = time.time()
    pass1_ported, pass1_stats = port_symbols(
        src_named, src_text_rva, src_text,
        tgt_text_rva, tgt_text, tgt_idx,
        window=32, prefix_k=6, masked=False,
        progress_every=5000,
    )
    print(f"Pass 1: {len(pass1_ported)}/{len(src_named)} ported  "
          f"(noprefix={pass1_stats['no_prefix']}  ambig={pass1_stats['ambiguous_or_zero']}  "
          f"missing_src={pass1_stats['missing_src']})  ({time.time()-t3:.0f}s)")

    pass1_names = {n for n, _ in pass1_ported}
    misses = [(n, r) for (n, r) in src_named if n not in pass1_names]
    print(f"  misses to retry: {len(misses)}")

    # 7. Pass 2: masked 48-byte match on misses
    print("\n=== Pass 2: masked 48-byte match on misses ===")
    t4 = time.time()
    try:
        pass2_ported, pass2_stats = port_symbols(
            misses, src_text_rva, src_text,
            tgt_text_rva, tgt_text, tgt_idx,
            window=48, prefix_k=6, masked=True,
            progress_every=5000,
        )
    except ImportError as e:
        print(f"  capstone not available ({e}); skipping masked pass")
        pass2_ported, pass2_stats = [], {'ok': 0, 'no_prefix': 0, 'ambiguous_or_zero': 0, 'missing_src': 0}
    print(f"Pass 2: {len(pass2_ported)} additional matches  "
          f"(noprefix={pass2_stats['no_prefix']}  ambig={pass2_stats['ambiguous_or_zero']})  "
          f"({time.time()-t4:.0f}s)")

    # 8. Combine + dedupe (Pass 1 wins on duplicates)
    seen = set()
    rows = []
    for name, tgt_rva in pass1_ported:
        if name in seen:
            continue
        seen.add(name)
        rows.append((f"0x{tgt_image_base + tgt_rva:x}", name, "exact32"))
    for name, tgt_rva in pass2_ported:
        if name in seen:
            continue
        seen.add(name)
        rows.append((f"0x{tgt_image_base + tgt_rva:x}", name, "masked48"))

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["target_va", "name", "pass"])
        w.writerows(rows)

    print(f"\n=== Summary ===")
    print(f"  source named functions: {len(src_named)}")
    print(f"  pass 1 (exact32):       {len(pass1_ported)}")
    print(f"  pass 2 (masked48):      {len(pass2_ported)}")
    print(f"  total ported:           {len(rows)}")
    print(f"  hit rate:               {100.0 * len(rows) / max(len(src_named), 1):.1f}%")
    print(f"  output:                 {OUT_CSV}")


if __name__ == "__main__":
    main()
