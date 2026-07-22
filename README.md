# AI-Assisted SAST Benchmark for OWASP WebGoat

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-164%20passed-brightgreen.svg)]()

An offline, reproducible benchmark framework for evaluating LLM-assisted Static Application Security Testing (SAST) on Java repositories (OWASP WebGoat 2025.3 target).

---

## 🚀 Quick Start

### 1. Environment Setup
No external dependencies required for core harness execution (uses Python stdlib).

```bash
# Verify Python environment and repo state
python3 scripts/check_environment.py
```

### 2. Run End-to-End Experiment Scan
Execute the end-to-end benchmark scanner on WebGoat:

```bash
./scripts/run_scan.sh exp-d-optimized
```

### 3. Summarize Benchmark Results
Display comparative matrix across all experiment runs:

```bash
python3 scripts/summarize_results.py results
```

---

## 🛠️ Benchmark CLI Tools

| Command | Purpose |
| :--- | :--- |
| `./scripts/run_scan.sh <exp-id>` | Runs end-to-end experiment scan and validates outputs |
| `python3 -m harness.runner --config configs/optimized.yaml` | Main Python harness runner |
| `python3 scripts/validate_jsonl.py <file.jsonl>` | Validates JSONL structure, schema, line numbers, and relative paths |
| `python3 scripts/validate_findings.py <findings.jsonl>` | Validates findings against canonical `Finding` contract schema |
| `python3 scripts/convert_to_jsonl.py --input res.sarif --format sarif --output findings.jsonl` | Converts SARIF 2.1.0 or JSON into benchmark JSONL |
| `python3 scripts/deduplicate_findings.py -i raw.jsonl -o findings.jsonl` | Standalone CLI for multi-signal finding deduplication |
| `python3 scripts/summarize_results.py results` | Renders comparative experiment matrix table |

---

## 📊 Experiment Matrix

| Experiment | Harness Strategy | Config File | Output Artifacts |
| :--- | :--- | :--- | :--- |
| **Exp A — Baseline** | Generic audit prompt | `configs/baseline.yaml` | `results/exp-a-baseline/` |
| **Exp B — Vuln-Prompts** | Class-specific prompts | `configs/vulnerability_specific.yaml` | `results/exp-b-vuln-prompts/` |
| **Exp C — Indexed** | Symbol index & validator | `configs/indexed.yaml` | `results/exp-c-indexed/` |
| **Exp D — Optimized** | Full optimized pipeline | `configs/optimized.yaml` | `results/exp-d-optimized/` |

---

## 📁 Repository & Artifact Architecture

```text
├── configs/                  # Experiment & exclusion configurations
│   ├── exclusions.json       # Scan exclusion rules (build, target, generated)
│   ├── baseline.yaml         # Experiment A configuration
│   ├── vulnerability_specific.yaml # Experiment B configuration
│   ├── indexed.yaml          # Experiment C configuration
│   └── optimized.yaml        # Experiment D configuration
├── harness/                  # Core benchmark harness Python modules
│   ├── schemas.py            # Finding & Validation contracts
│   ├── repository.py         # Repository scanner (Phase 1)
│   ├── indexer.py            # Java AST symbol indexer (Phase 2)
│   ├── context_builder.py    # Selective context retrieval (Task 2.3)
│   ├── candidate_finder.py   # Source/sink rule engine & prefilter (Phase 3)
│   ├── model_client.py       # LLM provider adapter & instrumentation (Phase 5)
│   ├── cache.py              # Response cache engine (Task 5.3)
│   ├── investigator.py       # Candidate investigation agent (Phase 6)
│   ├── validator.py          # Independent validator engine (Phase 6)
│   ├── deduplicator.py       # Multi-signal deduplication engine (Phase 7)
│   ├── ground_truth.py       # Local ground truth & evaluation (Phase 9)
│   ├── metrics.py            # Timing & metrics calculator (Phase 11)
│   └── runner.py             # End-to-end orchestrator (Phase 12)
├── prompts/                  # Versioned analysis & validation prompts
├── skills/                   # Standardized security skill knowledge files
├── ground_truth/             # 36 WebGoat local ground truth records
├── reports/                  # Phase task reports & benchmark.md
├── scripts/                  # CLI tools & validators
├── tests/                    # Complete test suite (164 tests)
└── results/                  # Generated experiment outputs & metrics
```

---

## 🧪 Running Tests

Run the full test suite (164 tests passing 100%):

```bash
python3 -m unittest discover -s tests -v
```

---

## 📝 License & Citation

Licensed under the MIT License. See [CONTEXT.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/CONTEXT.md) and [PLAN.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/PLAN.md) for full benchmark specifications.
