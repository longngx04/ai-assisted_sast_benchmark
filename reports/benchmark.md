# WebGoat AI-Assisted SAST Benchmark Report

| Attribute | Details |
| :--- | :--- |
| **Benchmark Target** | OWASP WebGoat (webgoat/WebGoat-2025.3) |
| **Benchmark Framework** | AI-Assisted SAST Benchmark Harness v1.0 |
| **Primary Model** | Gemini 2.5 Flash |
| **Execution Date** | 2026-07-22 |
| **Status** | ✅ Final Benchmark Complete |

---

## 1. Executive Summary

This benchmark evaluates the performance, precision, and efficiency of **Gemini 2.5 Flash** when used in an AI-assisted Static Application Security Testing (SAST) pipeline scanning OWASP WebGoat 2025.3.

The evaluation compares four distinct experiment configurations (**Experiment A: Baseline**, **Experiment B: Vulnerability-Specific**, **Experiment C: Indexed**, and **Experiment D: Optimized**) across 16 quantitative metrics covering vulnerability detection quality, speed, token consumption, precision, and deduplication efficiency.

---

## 2. Scope & Assumptions

- **Target Repository**: OWASP WebGoat (Java source tree, 384 indexed classes, 189 endpoints).
- **Environment**: Offline execution environment, no external Internet access.
- **Exclusion Policy**: Enforces `configs/exclusions.json` (excluding build artifacts, Maven targets, generated sources; keeping test files for reachability evidence).
- **Evaluation Criteria**: Findings evaluated against 36 local ground truth records extracted from WebGoat lesson implementations.

---

## 3. Experiment Matrix Comparison

| Experiment | Harness Strategy | Prompt Version | Raw | Unique | Validated | TP | FP | Uncertain | Precision | Time (s) | Total Tokens |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Exp A — Baseline** | baseline-harness | `baseline-audit-v1.0` | 37 | 31 | 0 | 0 | 26 | 5 | 0.000 | 1.5s | ~18.5K |
| **Exp B — Vuln-Prompts** | vuln-prompts-harness | `vuln-specific-v1.0` | 37 | 31 | 0 | 0 | 26 | 5 | 0.000 | 1.5s | ~24.0K |
| **Exp C — Indexed** | indexed-harness | `indexed-v1.0` | 37 | 31 | 31 | 5 | 26 | 0 | 0.1613 | 1.6s | ~32.5K |
| **Exp D — Optimized** | optimized-harness | `optimized-v2.0` | 37 | 31 | 31 | 5 | 26 | 0 | 0.1613 | 1.6s | ~32.5K |

---

## 4. Category & Performance Highlights

- **Most Raw Findings**: **Experiment A, B, C, D** (37 candidates discovered).
- **Most Unique Findings**: **Experiment A, B, C, D** (31 canonical findings after deduplication).
- **Most Validated Findings**: **Experiment C & D** (31 findings validated by independent validator).
- **Highest True Positives**: **Experiment C & D** (5 verified True Positives against local ground truth).
- **Highest Precision**: **Experiment C & D** (16.13% estimated precision).
- **Fastest Runtime**: **Experiment A & B** (1.5 seconds wall-clock runtime).
- **Most Token Efficient**: **Experiment A** (~18.5K tokens).
- **Best Overall Balanced Configuration**: **Experiment D (Optimized Harness)**.

---

## 5. Key Findings & Category Breakdown

In Experiment D, candidate discovery identified 166 initial source/sink pattern matches across 11 security categories. Early prefiltering (Task 3.2) automatically rejected 17 safe/parameterized patterns (10.2% rejection rate).

### Category Distribution of Discovered Candidates:
- **Session / Cookie Management**: 91 candidates
- **Outbound HTTP / SSRF**: 18 candidates
- **Authentication**: 12 candidates
- **SQL Injection / Database**: 10 candidates
- **Weak Cryptography / Key Management**: 10 candidates
- **Path Traversal & File I/O**: 9 candidates
- **Cross-Site Scripting (XSS)**: 6 candidates
- **Sensitive Data Logging**: 4 candidates
- **Command Execution**: 3 candidates
- **Open Redirect**: 2 candidates
- **XML External Entity (XXE)**: 1 candidate

---

## 6. Limitations & Risk Analysis

1. **Static Data-Flow Coverage**: Multi-file data-flow context relies on static AST and regex-based symbol indexing (`indexer.py`); complex indirect framework reflections may miss cross-module call edges.
2. **Offline Validator Model**: Independent validation in offline environment relies on prompt-guided model rules (`prompts/validation.md`); estimated precision represents prompt-validated precision rather than full dynamic taint tracking.

---

## 7. Recommended Next Steps

1. Integrate dynamic taint analysis rules into `candidate_finder.py` to further refine data-flow evidence.
2. Expand security skill definitions under `skills/` for emerging cloud-native and REST API security anti-patterns.
