# WebGoat AI-Assisted SAST Benchmark

## Current status

The historical files under `results/exp-a-baseline` through
`results/exp-d-optimized` were produced with the offline mock provider. They
are retained as fixtures for regression tests only and must not be described as
Gemini measurements. In particular, their model, token, finding, and precision
values are not an accepted benchmark result.

The production path now requires a fresh experiment ID and a configured
`GEMINI_API_KEY`; it refuses to mix usage logs with an existing run. It records
provider token metadata, runtime, raw responses, normalized findings, and
validation partitions under `results/<experiment-id>/`.

## Run a real benchmark

```bash
export GEMINI_API_KEY='YOUR_GOOGLE_GEMINI_API_KEY'
./scripts/run_scan.sh optimized exp-d-gemini-optimized
python3 scripts/summarize_results.py results/exp-d-gemini-optimized
```

Run `baseline`, `vulnerability-specific`, and `indexed` with different new
experiment IDs to compare strategies. Do not use the old `exp-*` directories
for new measurements.

## Precision policy

`metrics.json` reports `estimated_precision: null` and
`precision_type: unavailable` unless the local ground-truth records have been
manually reviewed, their evidence is present in source, and the experiment
configuration explicitly sets `ground_truth_complete: true`. A validator
decision alone is not treated as true-positive ground truth.

The repository does not claim a Gemini true-positive count until a real run and
a complete reviewed ground-truth/judge dataset are supplied.
