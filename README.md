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

This opens an interactive menu:

```
============================================================
  Bethesda Ghidra Scripts
============================================================

  Tools:
    Ghidra      : 12.0.4
    Clang       : clang version 22.1.4
    Steamless   : OK
    Python pkgs : OK

  Executables:
    f4/ae: Fallout4.exe
    skyrim/ae: SkyrimSE.exe
    skyrim/se: SkyrimSE.exe

  Output:
    Import scripts : OK
    Ghidra project : OK

----------------------------------------
  1) Install prerequisites
  2) Update CommonLib submodules to latest
  3) Generate import scripts
  4) Run headless Ghidra import
  5) Open Ghidra
  6) Full rebuild (generate + import)
  7) Clean Ghidra project (start fresh)
  q) Quit
----------------------------------------
```

The status panel at the top shows what's installed and detected. Menu options:

| Option | What it does |
|--------|-------------|
| **1** | Installs Python packages (`pdbparse`, `pyghidra`), downloads Ghidra, LLVM/Clang, and Steamless if missing. Safe to run multiple times -- skips anything already installed. |
| **2** | Runs `git submodule update --init --recursive --remote` to pull the latest CommonLib and AddressLibraryDatabase commits. Run this when upstream CommonLib has new types or fixes. |
| **3** | Parses CommonLib headers with clang and generates the Ghidra import scripts under `ghidrascripts/`. Requires clang (option 1 installs it). The executable version is auto-detected to select the correct address library. |
| **4** | Runs the generated import scripts against your executables in headless Ghidra. Creates or updates the Ghidra project with all types, symbols, and signatures. Steam DRM is stripped automatically via Steamless. |
| **5** | Opens Ghidra with the project loaded. |
| **6** | Runs options 3 + 4 back-to-back. Use this after updating submodules or replacing an executable. |
| **7** | Deletes the Ghidra project and state file so the next import starts from scratch. |

**First-time setup:** run **1**, then **2**, then **6** (or just **6** if you
already have clang installed). After that, **5** opens Ghidra with everything
imported.

### Non-interactive mode

For CI or scripting, pass a subcommand instead of using the menu:

```bash
python run.py setup   # option 1 + 2: install tools and update submodules
python run.py build   # option 6: generate scripts + headless import
python run.py all     # setup + build + open Ghidra
```

### How it works

All binaries end up in a single Ghidra project at
`ghidraprojects/BethesdaGhidraScripts/`, organized into `/<game>/<version>/`
folders.

The address library for each executable is selected automatically based on
the detected PE version. For Skyrim AE, all versions from 1.6.317 to 1.6.1179
are supported via the AddressLibraryDatabase.

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
| Skyrim AE    | `exes/skyrim/ae` | auto-detected     | `powerof3/CommonLibSSE`   |
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

### Running pipeline scripts directly

The `run.py` menu is the recommended interface. If you need to run individual
pipeline steps (e.g. regenerating only one game, or importing a single target):

```bash
# Generate import scripts only (requires clang)
python scripts/commonlibsse/parse_commonlib_types.py   # Skyrim SE + AE
python scripts/commonlibf4/parse_commonlib_types.py    # Fallout 4 AE

# Run headless Ghidra import (requires generated scripts + Ghidra)
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
├── run.py                           Interactive launcher / menu
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
