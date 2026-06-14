#!/usr/bin/env bash
# generate_bench_fixtures.sh — build fixture files for redaction benchmarks.
#
# Copies (or concatenates) real Synthea patient bundles from the ml data
# directory into internal/fhir/testdata/ at four target sizes.
# When real data is not available, falls back to the synthetic generator
# embedded in the benchmark test.
#
# Usage:
#   ./scripts/generate_bench_fixtures.sh [SYNTHEA_DIR]
#
# SYNTHEA_DIR defaults to ../ml/data/raw/fhir relative to this repo root,
# or the value of the SYNTHEA_FHIR_DIR environment variable.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TESTDATA="$REPO_ROOT/internal/fhir/testdata"
SYNTHEA_DIR="${SYNTHEA_FHIR_DIR:-}"

# Search common developer paths when env var is not set.
if [[ -z "$SYNTHEA_DIR" ]]; then
    for candidate in \
        "$REPO_ROOT/../ml/data/raw/fhir" \
        "$HOME/developer/data/ml/data/raw/fhir" \
        "$HOME/Developer/data/ml/data/raw/fhir"; do
        if [[ -d "$candidate" ]]; then
            SYNTHEA_DIR="$candidate"
            break
        fi
    done
fi

mkdir -p "$TESTDATA"

echo "=== FHIR benchmark fixture generator ==="
echo "Synthea source : ${SYNTHEA_DIR:-<not found>}"
echo "Output         : $TESTDATA"
echo

# Helper: print file size in KB/MB.
human_size() {
    local bytes
    bytes=$(wc -c < "$1" | tr -d ' ')
    if (( bytes >= 1048576 )); then
        printf "%.1f MB" "$(echo "scale=1; $bytes/1048576" | bc)"
    else
        printf "%d KB" "$(( bytes / 1024 ))"
    fi
}

# merge_bundles <output_file> <target_bytes> <source_files...>
# Extracts entries from source bundles entry-by-entry (cycling across files if
# needed) until a running size estimate reaches target_bytes, then writes the
# merged Bundle to output_file.
merge_bundles() {
    local out="$1" target="$2"; shift 2
    python3 - "$out" "$target" "$@" <<'PYEOF'
import json, sys, itertools

out_path = sys.argv[1]
target   = int(sys.argv[2])
sources  = sys.argv[3:]

all_entries  = []
running_size = 0  # approximate entry-only byte count (no bundle wrapper overhead)
done = False

for src in itertools.cycle(sources):
    if done:
        break
    try:
        with open(src) as fh:
            bundle = json.load(fh)
    except Exception:
        continue
    for entry in bundle.get("entry", []):
        serialized = json.dumps(entry, separators=(",", ":"))
        all_entries.append(entry)
        running_size += len(serialized)
        # Stop when the entry payload reaches the target. The bundle wrapper
        # adds ~100 bytes of overhead — negligible at these sizes.
        if running_size >= target:
            done = True
            break

bundle = {
    "resourceType": "Bundle",
    "type":         "searchset",
    "total":        len(all_entries),
    "entry":        all_entries,
}
payload = json.dumps(bundle, separators=(",", ":"))
print(f"  {len(all_entries)} entries, {len(payload) // 1024} KB", flush=True)
with open(out_path, "w") as fh:
    fh.write(payload)
PYEOF
}

if [[ -n "$SYNTHEA_DIR" && -d "$SYNTHEA_DIR" ]]; then
    echo "Synthea data found — building fixtures from real FHIR output."
    echo

    mapfile -t SOURCES < <(find "$SYNTHEA_DIR" -maxdepth 1 -name "*.json" | sort | head -60)
    if (( ${#SOURCES[@]} == 0 )); then
        echo "ERROR: no .json files found in $SYNTHEA_DIR" >&2
        exit 1
    fi

    for spec in \
        "bundle_500KB.json:524288" \
        "bundle_2MB.json:2097152" \
        "bundle_5MB.json:5242880" \
        "bundle_15MB.json:15728640"; do
        name="${spec%%:*}"
        target="${spec##*:}"
        dest="$TESTDATA/$name"
        printf "Building %-20s " "$name..."
        merge_bundles "$dest" "$target" "${SOURCES[@]}"
        echo "  saved $(human_size "$dest")"
    done
else
    echo "WARNING: Synthea directory not found."
    echo "Fixtures will be generated synthetically when benchmarks run."
    echo
    echo "To build from real data, set SYNTHEA_FHIR_DIR:"
    echo "  SYNTHEA_FHIR_DIR=/path/to/fhir ./scripts/generate_bench_fixtures.sh"
fi

echo
echo "Run benchmarks:"
echo "  cd $REPO_ROOT && go test -bench=BenchmarkRedaction -benchmem ./internal/fhir/..."
