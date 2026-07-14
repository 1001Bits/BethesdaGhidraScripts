#!/usr/bin/env bash
# Build per-version F4 shift maps after improvement.
#
# The build-time patcher applies shift maps in the form
#   ref_slot (header layout) -> target_slot (binary layout)
# CommonLibF4 headers describe the F4 OG 1.10.163 layout, so OG is the
# canonical reference.  Each other version gets its own shift map
# computed by matching against OG.
#
# Prerequisites:
#   - F4 OG, NG, AE, VR all improved via scripts/core/enrich_via_ghidra.py
#     (run separately while each binary is loaded in Ghidra).
#   - F4 OG must be loaded in Ghidra at some point to populate
#     refs/f4_og_vtables.csv with fingerprints.
#
# Usage:
#   bash build_all_shift_maps.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="$SCRIPT_DIR/../core"
REFS="$SCRIPT_DIR/refs"

REF="$REFS/f4_og_vtables.csv"
if [[ ! -f "$REF" ]]; then
    echo "ERROR: canonical reference not found: $REF" >&2
    echo "Load F4 OG 1.10.163 in Ghidra and run:" >&2
    echo "  python3 $CORE/enrich_via_ghidra.py --in $REF --out $REF --program Fallout4.exe ..." >&2
    exit 2
fi

echo "=== Building per-version shift maps (reference: F4 OG) ==="
for v in f4_ng f4_ae f4_vr; do
    if [[ ! -f "$REFS/${v}_vtables.csv" ]]; then
        echo "  skip $v: $REFS/${v}_vtables.csv missing"; continue
    fi
    python3 "$CORE/build_shift_map.py" \
        --ref "$REF" --ref-label f4_og \
        --target "$REFS/${v}_vtables.csv" --target-label "$v" \
        --out "$REFS/shift_${v}.json"
done

echo
echo "Done.  Shift maps written to $REFS/shift_*.json"
echo "Run scripts/commonlibf4/parse_commonlib_types.py to apply them."
