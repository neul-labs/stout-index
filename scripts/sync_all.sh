#!/bin/bash
# Sync all brewx indexes
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-$(dirname "$SCRIPT_DIR")}"

echo "=== brewx-index sync ==="
echo "Output directory: $OUTPUT_DIR"
echo ""

cd "$SCRIPT_DIR"

# Ensure dependencies are installed
if command -v uv &> /dev/null; then
    echo "Using uv..."
    uv sync
    PYTHON="uv run python"
else
    echo "Using pip..."
    pip install -q requests zstandard
    PYTHON="python"
fi

echo ""
echo "=== Syncing Formulas ==="
$PYTHON sync.py --output "$OUTPUT_DIR"

echo ""
echo "=== Syncing Casks ==="
$PYTHON sync_casks.py --output "$OUTPUT_DIR" 2>/dev/null || echo "Cask sync not available yet"

echo ""
echo "=== Syncing Linux Apps ==="
$PYTHON sync_linux_apps.py --output "$OUTPUT_DIR" 2>/dev/null || echo "Linux apps sync not available yet"

echo ""
echo "=== Syncing Vulnerabilities ==="
$PYTHON sync_vulns.py --output "$OUTPUT_DIR" 2>/dev/null || echo "Vulnerability sync not available yet"

echo ""
echo "=== Updating Manifest ==="
$PYTHON update_manifest.py --output "$OUTPUT_DIR"

echo ""
echo "=== Sync Complete ==="
echo ""

# Show summary
if [ -f "$OUTPUT_DIR/manifest.json" ]; then
    echo "Manifest:"
    cat "$OUTPUT_DIR/manifest.json"
fi
