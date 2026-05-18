#!/usr/bin/env bash
# Dump Skyrim SE/AE/VR primary vtable layouts via Ghidra MCP.
#
# Prerequisites: SkyrimSE.exe (1.5.97), SkyrimSE.exe (1.6.1170 = AE), and
# SkyrimVR.exe.unpacked.exe all loaded in Ghidra.  Both Skyrim flat
# binaries share the program_name "SkyrimSE.exe" -- Ghidra disambiguates
# by which is active, so you may need to switch the active program
# between runs.
#
# Skyrim has no pre-existing cross-version vtable map (unlike Fallout 4),
# so this script extracts each binary's actual layout from scratch via
# classes get_info + per-slot get_function_signature.
#
# Hot-class list: methods mod authors hook + their inheritance bases.
# Skyrim's CommonLibSSE puts Actor in the +0x0AD-region; the rest of the
# Bethesda RE chain (TESObjectREFR, TESForm, etc) covers the other hot
# vfuncs.
#
# Wall time: ~30 min per binary for the hot-class list.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="$SCRIPT_DIR/../core"
REFS="$SCRIPT_DIR/refs"
mkdir -p "$REFS"

# Curated hot-class list.  Concrete classes (instantiated in the binary)
# whose primary vtables MSVC actually emits.  Abstract bases like Actor
# show up only inside derived classes' vtables -- their slots come "for
# free" inside PlayerCharacter / Character.
CLASSES="PlayerCharacter,Character,TESObjectREFR,TESForm,BaseFormComponent,NiNode,NiAVObject,TESObjectWEAP,TESObjectARMO,TESNPC,bhkCharProxyController,bhkCharRigidBodyController,BSScript::Internal::CodeTasklet,BGSDefaultObjectManager,Main"

usage() {
    echo "Usage: $0 <version-label>" >&2
    echo "  versions: se | ae | svr" >&2
    echo "" >&2
    echo "Examples:" >&2
    echo "  $0 se    # dumps active SkyrimSE.exe -> refs/se_vtables.csv"
    echo "  $0 ae    # dumps active SkyrimSE.exe -> refs/ae_vtables.csv"
    echo "  $0 svr   # dumps SkyrimVR.exe.unpacked.exe -> refs/svr_vtables.csv"
    exit 1
}
[[ $# -ne 1 ]] && usage

VER="$1"
case "$VER" in
    se)  PROG="SkyrimSE.exe" ;;
    ae)  PROG="SkyrimSE.exe" ;;
    svr) PROG="SkyrimVR.exe.unpacked.exe" ;;
    *)   usage ;;
esac

OUT="$REFS/${VER}_vtables.csv"

# Seed the CSV with the class header if it doesn't exist yet
if [[ ! -f "$OUT" ]]; then
    echo "class,vtable_addr,slot,func_addr,func_name,fingerprint" > "$OUT"
fi

echo "Dumping Skyrim $VER (program=$PROG) -> $OUT"
echo "  classes: $CLASSES"

python3 "$CORE/vtable_dumper.py" \
    --program "$PROG" \
    --label "$VER" \
    --classes "$CLASSES" \
    --out "$OUT"
