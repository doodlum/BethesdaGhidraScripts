# Per-Version Vtable Layout Pipeline

## What this solves

CommonLib headers (CommonLibSSE, CommonLibF4, CommonLibSF) declare ONE
vtable layout per class. But the actual binary layout drifts between
patch revisions and runtimes:

| Runtime | Drift vs CommonLib header layout |
|---|---|
| Skyrim SE 1.5.97 | none (canonical) |
| Skyrim AE 1.6.1170 | none |
| Skyrim VR 1.4.15 | +2 slots in Actor (insertion before KillDying) |
| Fallout 4 OG 1.10.163 | header reference |
| Fallout 4 NG 1.10.984 | drifted (under verification) |
| Fallout 4 AE/late patch | drifted significantly (PC::Update at slot 0xC6 vs 0xCF) |
| Fallout 4 VR 1.2.72 | +1 slot (insertion between UpdateNoAI and UpdateMotionDrivenState) |
| Starfield 1.15.x | single version |

Without per-version correction, the generated `CommonLibImport_<VER>.py`
script applies the header's vtable struct overlay to the binary's actual
vtable. Field names (`Update`, `UpdateNoAI`, etc.) end up at the wrong
byte offsets, mislabeling whatever is actually at those slots.

## Pipeline overview

```
                   (one-time per binary version)
  +-----------+      +------------------+      +-------------------+
  | Binary    | ---> | vtable_dumper.py | ---> | <ver>_vtables.csv |
  | in Ghidra |      | (or legacy       |      |   (one per binary)|
  +-----------+      |  importer)       |      +---------+---------+
                     +------------------+                |
                                                         v
                                              +----------+----------+
                                              | build_shift_map.py  |
                                              | (ref + target -->   |
                                              |  shift_<ver>.json)  |
                                              +----------+----------+
                                                         |
                              (every build run)          v
  +----------+    +-------------------+    +-------------+----------+
  | CommonLib| -> | _build_vtable_    | -> | _patch_vtable_structs  |
  | headers  |    | structs (AST)     |    | (apply shift map)      |
  +----------+    +-------------------+    +------------+-----------+
                                                        |
                                                        v
                                            +-----------+-----------+
                                            | _verify_anchors_or_   |
                                            | exit (safety net)     |
                                            +-----------+-----------+
                                                        |
                                                        v
                                            +-----------+-----------+
                                            | generate_script       |
                                            | CommonLibImport_<VER> |
                                            +-----------------------+
```

## Layered safety

Three independent layers verify vtable correctness:

1. **Shift map application** (`vtable_patcher.py`) — re-targets the
   header-shaped vtable struct to the version's actual binary layout
   using a per-version slot mapping derived from the dump.

2. **Anchor verifier** (`anchor_verifier.py`) — hand-maintained
   `(class, method, expected_slot)` truth table per version. Runs
   *after* the patcher. Fails the build on any mismatch. Catches:
   - Missing/stale shift maps
   - Header drift that the matcher couldn't resolve
   - Future patches that silently re-shuffle slots

3. **Per-version AST parse** — each target gets its own
   `collect_types` call with version-appropriate `-D` flags, so future
   header overlays (`#ifdef BGS_SKYRIM_VR` etc.) can drive layout
   differently per version without touching this code.

A missing shift map is non-fatal — the patcher just skips that
version. The anchor verifier then surfaces the resulting drift loudly.

## Adding a new version

Walkthrough for, say, Skyrim VR (assuming it's loaded in Ghidra as
`SkyrimVR.exe.unpacked.exe`):

```bash
# 1. Dump the binary's actual vtable layout
cd scripts/core
python3 vtable_dumper.py \
    --program SkyrimVR.exe.unpacked.exe \
    --label svr \
    --out ../commonlibsse/refs/svr_vtables.csv

# 2. Dump the reference (canonical) binary -- skip if already done
python3 vtable_dumper.py \
    --program SkyrimSE.exe \
    --label se \
    --out ../commonlibsse/refs/se_vtables.csv

# 3. Compute the shift map
python3 build_shift_map.py \
    --ref ../commonlibsse/refs/se_vtables.csv --ref-label se \
    --target ../commonlibsse/refs/svr_vtables.csv --target-label svr \
    --out ../commonlibsse/refs/shift_svr.json

# 4. Run the build -- patcher picks up the new shift map automatically
cd ..
python3 commonlibsse/parse_commonlib_types.py

# 5. (Optional) Add or refresh hand-verified anchors for that version
#    Edit scripts/commonlibsse/anchors/svr.csv to lock in known
#    PlayerCharacter::Update / Actor::UpdateNonRenderSafe slots.
```

## File map

| File | Purpose |
|---|---|
| `core/vtable_layout.py` | `BinaryLayout` / `ClassVtable` / `SlotEntry` data model + CSV I/O |
| `core/vtable_dumper.py` | Live Ghidra MCP client, dumps per-binary vtables |
| `core/vtable_import_legacy.py` | Convert pre-existing on-disk dumps (`f4vr_vtables.txt`, `f4ng_vtables.csv`) to unified format |
| `core/vtable_matcher.py` | Match ref ↔ target slots by name + fingerprint, emit shift map |
| `core/build_shift_map.py` | CLI wrapping matcher (ref + target -> shift JSON) |
| `core/vtable_patcher.py` | Apply shift map to `vtable_structs` at build time |
| `core/anchor_verifier.py` | Per-version anchor truth-table verifier (fatal on drift) |
| `<commonlib>/refs/<ver>_vtables.csv` | Per-version dumped vtable layout (input) |
| `<commonlib>/refs/shift_<ver>.json` | Per-version shift map (output of build_shift_map) |
| `<commonlib>/anchors/<ver>.csv` | Hand-verified anchor truth table |

## Cross-version matching strategy

Two signals, in priority order:

1. **Exact name match**: same PDB-resolved function name appears in both
   binaries. Slot positions can differ but the function identity is
   unambiguous. Strongest signal when PDB symbols are available
   (Skyrim SE, F4 OG, F4 NG to a degree).

2. **Fingerprint match**: Ghidra's masked byte-pattern signature for
   the function body. Survives address relocation across versions
   because relocation bytes are masked with `?`. The dumper captures
   these via `get_function_signature`; the matcher's
   `_fingerprints_match` requires ≥8 concrete matching bytes to avoid
   false positives.

Anything matched by neither signal becomes either an "unmatched ref
slot" (dropped from version's vtable struct) or "target-only slot"
(emitted as `__<ver>_only_0xXX` placeholder).

## Known limitations

- **Legacy importer is name-poor**: `f4vr_vtables.txt`-style dumps only
  carry slot indices and function addresses, no PDB names or
  fingerprints. Cross-version matching from a legacy import has 0
  signal — it can populate a target layout but not match against a
  reference. Re-dump with `vtable_dumper.py` to get fingerprints.

- **Multiple-inheritance secondary vtables are skipped**: only the
  primary class vtable (no `_<N>` suffix) is captured. Most virtual
  dispatch we care about happens on the primary vtable; secondary
  vtables are for EventSink interfaces and similar adjustor thunks.

- **Anchor verifier only spot-checks**: it does not validate every
  slot, only those in the anchor CSV. Add anchors broadly to catch
  more drift.
