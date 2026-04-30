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
exes/skyrim/se/SkyrimSE.exe      Skyrim SE  (1.5.97)
exes/skyrim/ae/SkyrimSE.exe      Skyrim AE  (1.6.1170+)
exes/f4/ae/Fallout4.exe          Fallout 4  (1.11.191)
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
| Fallout 4 AE | `exes/f4/ae`    | `1-11-191-0`     | `libxse/commonlibf4`      |

You don't need all three. The script detects which executables are present and
only generates and runs what's needed.

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
├── ghidra/                          Ghidra install (auto-downloaded)
└── tools/                           Steamless, LLVM (auto-downloaded)
```

---
