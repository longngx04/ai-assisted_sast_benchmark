#!/usr/bin/env bash
# Script to run a SAST scan experiment (Phase 12 / Micro-task 12.4)
set -e

EXPERIMENT="${1:-exp-d-optimized}"
CONFIG_FILE="configs/${EXPERIMENT#exp-}.yaml"

if [ ! -f "$CONFIG_FILE" ]; then
    CONFIG_FILE="configs/optimized.yaml"
fi

echo "=================================================="
echo " Running SAST Scan Experiment: $EXPERIMENT"
echo " Configuration: $CONFIG_FILE"
echo "=================================================="

python3 -m harness.runner \
  --config "$CONFIG_FILE" \
  --experiment-id "$EXPERIMENT" \
  --source webgoat/WebGoat-2025.3 \
  --output results \
  --model mock

echo "=================================================="
echo " Validating Outputs..."
echo "=================================================="

python3 scripts/validate_jsonl.py "results/$EXPERIMENT/findings.jsonl"
python3 scripts/validate_findings.py "results/$EXPERIMENT/findings.jsonl"

echo "Scan complete. Outputs generated in results/$EXPERIMENT/"
