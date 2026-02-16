#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

# Usage:
#   ./test-image.sh <image>
#
# Description:
#   This script tests release pisc image by running a security scan.
#   If the image name includes the word "feeds", it is treated as an offline image
#   and the scan will be executed with '--offline-feeds'.
#   Otherwise, the scan will run in online mode.
#
# Environment variables:
#   VT_API_KEY

set -Eeo pipefail

IMAGE="${1:-}"
# get exported var with default value if it is empty
: "${OUT_DIR:=/tmp}"

if [[ -z "$IMAGE" ]]; then
    echo "Usage: $0 <image>"
    echo "Example: $0 kapistka/pisc:v0.19.0"
    echo "         $0 kapistka/pisc:v0.19.0-feeds"
    exit 2
elif [[ "$IMAGE" != *"feeds"* ]]; then
    OFFLINE_FLAG=''
else
    OFFLINE_FLAG='--offline-feeds'
fi

LOG_FILE=$(pwd)/log.txt
touch $LOG_FILE
INPUT_FILE="$(pwd)/images.txt"
if [[ -z "$VT_API_KEY" ]]; then
    echo "VT_API_KEY not found"
    echo "Exit code = $EXIT_CODE"
    exit 2
fi

cat > $INPUT_FILE <<EOF
r0binak/mtkpi:v1.3
EOF

echo "run $IMAGE"

set +e
docker run --rm \
    -v "$INPUT_FILE":$OUT_DIR"/images.txt" \
    "$IMAGE" \
    /bin/bash /home/nonroot/scan.sh -delm "$OFFLINE_FLAG" --virustotal-key "$VT_API_KEY" -f $OUT_DIR"/images.txt" \
    2>&1 | tee "$LOG_FILE"
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 ]]; then
    echo "Scan return good result - it is problem"
    echo "Exit code = $EXIT_CODE"
    exit $EXIT_CODE
elif [[ $EXIT_CODE -eq 1 ]]; then
    echo "Scan finished with no errors"
else
    echo "Scan Errors (exit $EXIT_CODE)."
    grep -i "error" "$LOG_FILE" && echo "Check log: $LOG_FILE"
    echo "Exit code = $EXIT_CODE"
    exit $EXIT_CODE
fi

echo "Checking good content..."
REQUIRED=("virustotal detected" "exploitable vulnerabilities" "dangerous misconfiguration" "created: " "newer tags")
for pattern in "${REQUIRED[@]}"; do
    if ! grep -q "$pattern" "$LOG_FILE"; then
        echo "Missing expected pattern: $pattern"
        echo "Exit code = 2"
        exit 2
    fi
done

echo "Checking for errors..."
BAD=("error")
for pattern in "${BAD[@]}"; do
    if grep -q "$pattern" "$LOG_FILE"; then
        echo "Found error pattern: $pattern"
        echo "Exit code = 2"
        exit 2
    fi
done

echo "Test passed!"

exit 0
