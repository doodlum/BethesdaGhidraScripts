#!/usr/bin/env python3
"""Cross-version byte-signature port for Fallout 4 binaries.

CommonLibF4's IDs live in the NG/AE namespace (1.10.984 / 1.11.191).  OG
(1.10.163) and VR (1.2.72) use disjoint ID namespaces, so address-library
lookups can't transfer names directly.  This driver anchors at AE-named
functions (~25k from CommonLibImport_F4_AE.py + IDAImportNames) and finds
matching positions in OG / NG / VR via masked byte signatures.

Pipeline:
  Source pool:  CommonLibImport_F4_AE.py SYMBOLS + extras/IDAImportNames_*.py
  Signatures:   bytesig_port.py  (exact 32 B match + masked 48 B retry)
  Output:       OG/NG/VR scripts re-emitted with ported names embedded

Two-pass match:
  Pass 1 — exact 32-byte raw match  (high precision, lower recall)
  Pass 2 — 48-byte masked match wildcarding rel32 / rip-rel disp32 operands
           (cross-build resilient — OG/VR have different jump targets)

Only runs if both the source (AE) and target (OG / NG / VR) binaries are
present under exes/f4/<version>/.  Missing binaries are silently skipped.
Steam binaries with SteamStub DRM are auto-unpacked via Steamless.

Usage:
  python scripts/commonlibf4/run_bytesig_port.py             # all targets
  python scripts/commonlibf4/run_bytesig_port.py og          # one target
  python scripts/commonlibf4/run_bytesig_port.py og ng vr    # multiple
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


_SCRIPT_DIR  = Path(__file__).resolve().parent
_PROJECT_DIR = _SCRIPT_DIR.parent.parent
sys.path.insert(0, str(_PROJECT_DIR / "scripts" / "core"))

from bytesig_port import load_pe_text, build_prefix_index, port_symbols  # noqa: E402
from steamless     import ensure_unpacked                                # noqa: E402


EXES_DIR       = _PROJECT_DIR / "exes" / "f4"
GENERATED_DIR  = _PROJECT_DIR / "ghidrascripts"
EXTRAS_DIR     = _PROJECT_DIR / "extras"
STEAMLESS_CLI  = _PROJECT_DIR / "tools" / "Steamless" / "Steamless.CLI.exe"

VERSION_TO_BIN_NAME = {
    "og": "Fallout4.exe",
    "ng": "Fallout4.exe",
    "ae": "Fallout4.exe",
    "vr": "Fallout4VR.exe",
}


def _binary_for(target: str) -> Path | None:
    """Return the unpacked binary path for target, or None if not present."""
    name = VERSION_TO_BIN_NAME.get(target)
    if not name:
        return None
    raw = EXES_DIR / target / name
    if not raw.is_file():
        return None
    return ensure_unpacked(raw, STEAMLESS_CLI)


_NAME_RE = re.compile(r"^[A-Za-z_][\w:]*$")


def _load_commonlib_f4_names(source: str) -> dict[str, int]:
    """{name: source_rva} from CommonLibImport_F4_{SOURCE}.py SYMBOLS array.

    ``source`` is 'ae' or 'ng'; the matching RVA key on each symbol is 'a' or
    'ng' respectively (set up by parse_commonlib_types.py).
    """
    rva_key = "a" if source == "ae" else source
    script = GENERATED_DIR / f"CommonLibImport_F4_{source.upper()}.py"
    if not script.is_file():
        return {}
    content = script.read_text(encoding="utf-8")
    m = re.search(r"^SYMBOLS = (.+?)$", content, re.M)
    if not m:
        return {}
    syms = json.loads(m.group(1))
    out: dict[str, int] = {}
    for s in syms:
        if s.get("t") != "func":
            continue
        rva = s.get(rva_key)
        name = s.get("n", "")
        if not rva or not name or "<" in name or ">" in name:
            continue
        out.setdefault(name, rva)
    return out


def _load_ida_names() -> dict[str, int]:
    """{name: rva} from extras/IDAImportNames_1.11.191.0.py (AE-keyed)."""
    p = EXTRAS_DIR / "IDAImportNames_1.11.191.0.py"
    if not p.is_file():
        return {}
    name_re = re.compile(
        r"^\s*NAME\(\s*0x([0-9A-Fa-f]+)\s*,\s*['\"]([^'\"]+)['\"]\s*\)\s*$")
    addr_suffix_re = re.compile(r"_[0-9A-Fa-f]{6,12}$")
    placeholder_re = re.compile(
        r"^(?:FUN|sub|loc|byte|word|dword|qword|unk|off|stru|asc|jpt|nullsub|j_)"
        r"_[0-9A-Fa-f]+$")
    image_base = 0x140000000
    out: dict[str, int] = {}
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = name_re.match(line)
            if not m:
                continue
            try:
                abs_addr = int(m.group(1), 16)
            except ValueError:
                continue
            if abs_addr < image_base or abs_addr >= image_base + 0x80000000:
                continue
            rva = abs_addr - image_base
            raw = m.group(2).strip()
            if placeholder_re.match(raw):
                continue
            name = addr_suffix_re.sub("", raw).strip()
            if not name or not _NAME_RE.match(name):
                continue
            out.setdefault(name, rva)
    return out


def _merge_into_script(target: str, target_rva_key: str,
                       ported: list[tuple[str, int]]) -> int:
    """Inject ported (name, target_rva) entries into the target's generated
    script's SYMBOLS array.  Returns the number of new entries added.

    The script's SYMBOLS line is rewritten in place — entries whose name is
    already present in SYMBOLS get a target_rva_key field added; new names
    are appended as fresh entries.  Existing AE/NG offsets stay intact.
    """
    fname = f"CommonLibImport_F4_{target.upper()}.py"
    script = GENERATED_DIR / fname
    if not script.is_file():
        print(f"  {fname}: not found, skipping merge")
        return 0
    content = script.read_text(encoding="utf-8")
    m = re.search(r"^SYMBOLS = (.+?)$", content, re.M)
    if not m:
        print(f"  {fname}: no SYMBOLS array, skipping merge")
        return 0

    syms = json.loads(m.group(1))
    by_name: dict[str, dict] = {}
    for s in syms:
        if s.get("t") == "func":
            by_name.setdefault(s["n"], s)

    added = augmented = 0
    for name, rva in ported:
        existing = by_name.get(name)
        if existing is not None and target_rva_key not in existing:
            existing[target_rva_key] = rva
            existing.setdefault("src_bytesig", "AE-bytesig-port")
            augmented += 1
        elif existing is None:
            syms.append({
                "n": name, "t": "func", "sig": "",
                target_rva_key: rva,
                "src": "AE-bytesig-port",
            })
            added += 1
    new_blob = "SYMBOLS = " + json.dumps(syms, separators=(",", ":"))
    content = content[:m.start()] + new_blob + content[m.end():]
    script.write_text(content, encoding="utf-8")
    print(f"  {fname}: merged {augmented} augmented + {added} new entries "
          f"({len(ported)} ported)")
    return augmented + added


TARGET_TO_RVA_KEY = {"og": "og", "ng": "ng", "vr": "v"}


def run(targets: list[str]) -> None:
    print("=== Fallout 4 cross-version byte-signature port ===")

    # Source binary preference: AE first (has IDA fallback names), then NG
    # (shares the same ID namespace as AE).  NG is a useful fallback when
    # the user only has the NG patch installed locally.
    src_ver = None
    src_path = None
    for cand in ("ae", "ng"):
        p = _binary_for(cand)
        if p is not None and p.is_file():
            src_ver, src_path = cand, p
            break
    if src_ver is None:
        print("  Neither AE nor NG binary present in exes/f4/ — skipping "
              "byte-sig port (OG/VR will have types-only coverage).")
        return
    print(f"  Source binary: F4 {src_ver.upper()} ({src_path.name})")

    name_to_src_rva: dict[str, int] = {}
    primary = _load_commonlib_f4_names(src_ver)
    print(f"  CommonLibImport_F4_{src_ver.upper()}.py: {len(primary):,} names")
    name_to_src_rva.update(primary)

    if src_ver == "ae":
        ida = _load_ida_names()
        new_ida = sum(1 for n in ida if n not in name_to_src_rva)
        print(f"  IDAImportNames_1.11.191.0.py: {len(ida):,} names ({new_ida} new)")
        for n, rva in ida.items():
            name_to_src_rva.setdefault(n, rva)

    print(f"  Source name pool: {len(name_to_src_rva):,} unique")
    print(f"  Loading source binary: {src_path}")
    _, src_text_rva, src_text = load_pe_text(str(src_path))
    print(f"    .text RVA={src_text_rva:#x} size={len(src_text):,}")

    src_rvas = list(name_to_src_rva.items())

    for tgt in targets:
        if tgt == src_ver:
            continue  # don't port a binary to itself
        tgt_path = _binary_for(tgt)
        if tgt_path is None or not tgt_path.is_file():
            print(f"  {tgt.upper()}: binary not present in exes/f4/{tgt}/ — "
                  f"skipping")
            continue
        print(f"\n  --- {src_ver.upper()} -> {tgt.upper()} ---")
        print(f"  Loading {tgt.upper()} binary: {tgt_path.name}")
        _, tgt_text_rva, tgt_text = load_pe_text(str(tgt_path))
        print("  Building prefix index ...")
        tgt_idx = build_prefix_index(tgt_text, k=6)
        print(f"    {len(tgt_idx):,} unique 6-byte prefixes")

        print("  Pass 1: exact 32-byte match ...")
        ported, stats = port_symbols(
            src_rvas, src_text_rva, src_text,
            tgt_text_rva, tgt_text, tgt_idx,
            window=32, prefix_k=6, masked=False, progress_every=0)
        print(f"    exact: ok={stats['ok']:,} no_prefix={stats['no_prefix']:,} "
              f"ambig={stats['ambiguous_or_zero']:,} miss_src={stats['missing_src']:,}")

        ported_names = {n for n, _ in ported}
        unmatched = [(n, r) for (n, r) in src_rvas if n not in ported_names]
        if unmatched:
            print(f"  Pass 2: masked 48-byte retry on {len(unmatched):,} unmatched ...")
            try:
                ported2, stats2 = port_symbols(
                    unmatched, src_text_rva, src_text,
                    tgt_text_rva, tgt_text, tgt_idx,
                    window=48, prefix_k=6, masked=True, progress_every=0)
                ported.extend(ported2)
                print(f"    masked: ok={stats2['ok']:,} "
                      f"no_prefix={stats2['no_prefix']:,} "
                      f"ambig={stats2['ambiguous_or_zero']:,}")
            except ImportError as e:
                print(f"    SKIPPED ({e}) — install capstone+numpy for the "
                      f"cross-build masked-retry pass")

        rva_key = TARGET_TO_RVA_KEY[tgt]
        _merge_into_script(tgt, rva_key, ported)


def main() -> None:
    args = [a.lower() for a in sys.argv[1:]] or ["og", "ng", "vr"]
    bad = [a for a in args if a not in ("og", "ng", "ae", "vr")]
    if bad:
        print(f"Unknown target(s): {bad}")
        print("Usage: python run_bytesig_port.py [og] [ng] [vr]")
        sys.exit(2)
    run(args)


if __name__ == "__main__":
    main()
