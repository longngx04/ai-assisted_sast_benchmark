#!/usr/bin/env bash
# Script to run a SAST scan experiment (Phase 12 / Micro-task 12.4)
set -e

STRATEGY="${1:-optimized}"
EXPERIMENT="${2:-}"
if [ -z "$EXPERIMENT" ]; then
    echo "Usage: $0 <baseline|vulnerability-specific|indexed|optimized> <new-experiment-id>" >&2
    exit 2
fi

case "$STRATEGY" in
  baseline) CONFIG_FILE="configs/baseline.yaml" ;;
  vulnerability-specific) CONFIG_FILE="configs/vulnerability_specific.yaml" ;;
  indexed) CONFIG_FILE="configs/indexed.yaml" ;;
  optimized) CONFIG_FILE="configs/optimized.yaml" ;;
  *) echo "Unknown strategy: $STRATEGY" >&2; exit 2 ;;
esac

echo "=================================================="
echo " Running SAST Scan Experiment: $EXPERIMENT"
echo " Configuration: $CONFIG_FILE"
echo "=================================================="

python3 -m harness.runner \
  --config "$CONFIG_FILE" \
  --experiment-id "$EXPERIMENT" \
  --source webgoat/WebGoat-2025.3 \
  --output results

echo "=================================================="
echo " Validating Outputs..."
echo "=================================================="

python3 scripts/validate_jsonl.py "results/$EXPERIMENT/findings.jsonl"
python3 scripts/validate_findings.py "results/$EXPERIMENT/findings.jsonl"

echo "Scan complete. Outputs generated in results/$EXPERIMENT/"
