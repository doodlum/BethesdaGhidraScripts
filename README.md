# Bethesda Ghidra Scripts

Automatically imports CommonLib type definitions, vtable layouts, function
signatures, and address-library symbols into Ghidra for Bethesda game binaries.

## Quick start

1. Clone the repo:

```bash
git clone https://github.com/doodlum/BethesdaGhidraScripts.git
cd BethesdaGhidraScripts
```

2. Drop your game executables into the matching folders (any combination):

```
exes/skyrim/se/SkyrimSE.exe      Skyrim SE    (1.5.97)
exes/skyrim/ae/SkyrimSE.exe      Skyrim AE    (1.6.1170+)
exes/skyrim/vr/SkyrimVR.exe      Skyrim VR    (1.4.15)
exes/f4/og/Fallout4.exe          Fallout 4 OG (1.10.163) — types only
exes/f4/ng/Fallout4.exe          Fallout 4 NG (1.10.984)
exes/f4/ae/Fallout4.exe          Fallout 4 AE (1.11.191)
exes/f4/vr/Fallout4VR.exe        Fallout 4 VR (1.2.72)   — types only
```

3. Run:

```bash
python run.py
```

That's it. Everything else is handled automatically:

- **Git submodules** updated to the latest upstream commits
- **Python packages** (`pdbparse`, `pyghidra`) installed if missing
- **LLVM/Clang** downloaded locally if not already on your system
- **Ghidra** downloaded and extracted if not already present
- **Steam DRM** detected and stripped via [Steamless](https://github.com/atom0s/Steamless) (downloaded automatically on Windows)
- **Import scripts** generated from CommonLib headers via clang
- **Headless Ghidra import** with full type/symbol application and verification

All binaries end up in a single Ghidra project at
`ghidraprojects/BethesdaGhidraScripts/`, organized into `/<game>/<version>/`
folders.

### Requirements

- **Python 3.10+** (64-bit)
- **Git**

Clang, Ghidra, Steamless, and Python packages are all fetched automatically on
first run.

---

## Supported games

| Game         | Folder           | Address library  | CommonLib                 |
|--------------|------------------|------------------|---------------------------|
| Skyrim SE    | `exes/skyrim/se` | `1-5-97-0`       | `powerof3/CommonLibSSE`   |
| Skyrim AE    | `exes/skyrim/ae` | `1-6-1170-0`     | `powerof3/CommonLibSSE`   |
| Skyrim VR    | `exes/skyrim/vr` | `1-4-15-0` (csv) | `powerof3/CommonLibSSE`   |
| Fallout 4 OG | `exes/f4/og`     | `1-10-163-0`     | `libxse/commonlibf4`      |
| Fallout 4 NG | `exes/f4/ng`     | `1-10-984-0`     | `libxse/commonlibf4`      |
| Fallout 4 AE | `exes/f4/ae`     | `1-11-191-0`     | `libxse/commonlibf4`      |
| Fallout 4 VR | `exes/f4/vr`     | `1-2-72-0` (csv) | `libxse/commonlibf4`      |

You don't need all of them. The script detects which executables are present
and only generates and runs what's needed.

Skyrim VR shares the SE-derived ID namespace with SE/AE, so the same
`CommonLibSSE` headers generate a VR-targeting script that resolves SE IDs
against the VR address library.  The VR address library ships as a CSV
(community-maintained) rather than meh321's binary format.

CommonLibF4's IDs sit in the NG/AE namespace (1.10.984 / 1.11.191), so those
two versions get full type + function symbol coverage from the address
library alone.  F4 OG (1.10.163) and F4 VR (1.2.72) use disjoint ID
namespaces that CommonLibF4 does not reference; the address library can't
transfer names directly because looking up an AE-namespace ID against the
OG or VR DB only finds coincidental low-ID matches at wrong addresses.

To get function names onto OG and VR anyway, the F4 pipeline runs a
cross-version byte-signature port (`scripts/commonlibf4/run_bytesig_port.py`)
after script generation.  Anchored at AE (or NG when AE is absent), it scans
each AE-named function's first 32 bytes for an exact, unique match in the
OG/VR binary; unmatched names get a 48-byte masked retry that wildcards
rel32 and rip-relative operands so cross-build jump targets stop confusing
the match.  Matched (name, target_rva) pairs are merged back into the
generated `CommonLibImport_F4_OG.py` / `_VR.py` scripts so they apply
function names alongside the types when the script runs.

The byte-sig port only runs when both AE (or NG) and the target binary are
present in `exes/f4/`; without them, OG/VR fall back to types-only coverage.

---

## What gets imported

Each binary receives:

- All enums, structs, and classes from CommonLib headers with exact field
  offsets and sizes (parsed via clang `-ast-dump` and `-fdump-record-layouts`)
- Primary and secondary vtable structs for multi-inheritance hierarchies
- Virtual function names from vtable address walks
- Function signatures built from CommonLib type descriptors
- Address-library symbols (function labels, RTTI, vtable pointers)
- Fallback symbols from PDB (`SkyrimSE.pdb`) and IDA scripts where available
- `Source:` plate comments on named functions showing which symbol table
  provided the name

### Accuracy

Every emitted struct field and signature parameter uses the **exact** type from
the source. Anything that can't be pinned to an exact type is left as `void *`
rather than guessed. In practice ~99.75% of struct fields are fully typed.

| | F4 AE | Skyrim AE | Skyrim SE |
| --- | --- | --- | --- |
| Struct fields | 24,216 | 34,243 | 34,231 |
| Fully typed | 99.76% | 99.75% | 99.75% |
| Vtable structs | 1,292 | 2,023 | 2,024 |

---

## Advanced usage

### Running individual steps

The `run.py` script runs the full pipeline. If you only need part of it:

```bash
# Generate import scripts only (requires clang)
python scripts/commonlibsse/parse_commonlib_types.py   # Skyrim SE + AE
python scripts/commonlibf4/parse_commonlib_types.py    # Fallout 4 AE

# Run headless Ghidra import only (requires generated scripts + Ghidra)
python scripts/run_headless.py                # all targets
python scripts/run_headless.py skyrim         # all skyrim versions
python scripts/run_headless.py skyrim ae      # specific target
python scripts/run_headless.py f4 ae
```

### Symbol priority

Symbols are applied in priority order. Higher-priority sources take precedence:

1. `RELOCATION_ID(SE, AE)` / `REL::ID` macros (CommonLib)
2. `Offsets_RTTI.h`, `Offsets_NiRTTI.h`, `Offsets_VTABLE.h` labels
3. `RE::Offset::` namespace IDs (Skyrim)
4. CommonLibSSE `src/*.cpp` cross-references (Skyrim only)
5. AE rename DB (`skyrimae.rename`) -- Skyrim AE only
6. PDB public symbols (`SkyrimSE.pdb`) -- Skyrim
7. IDA names (`IDAImportNames_1.11.191.0.py`) -- Fallout 4 AE

### Project layout

```
.
├── run.py                           One-click setup and run
├── extern/                          CommonLib submodules (auto-updated)
├── addresslibrary/                  Address library .bin files
├── extras/                          Fallback symbol sources (PDB, IDA)
├── exes/                            Game executables (you provide these)
├── scripts/                         Pipeline source code
│   ├── run_headless.py              Headless Ghidra runner
│   ├── core/                        Shared: clang parser, script emitter
│   ├── commonlibsse/                Skyrim SE/AE pipeline
│   └── commonlibf4/                 Fallout 4 AE pipeline
├── ghidrascripts/                   Generated import scripts (output)
├── ghidraprojects/                  Ghidra project (output)
└── tools/                           Ghidra, Steamless, LLVM (auto-downloaded)
```

---
