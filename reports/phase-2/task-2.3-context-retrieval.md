# Task 2.3 — Context Retrieval

| Attribute | Details |
| :--- | :--- |
| **Task ID** | Task 2.3 |
| **Title** | Context retrieval |
| **Status** | ✅ Complete |
| **Phase** | Phase 2: Repository Reconnaissance & Indexing |
| **Date** | 2026-07-22 |

---

## 1. Objective

The objective of Task 2.3 is to implement [harness/context_builder.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/context_builder.py) — a selective context retrieval module that constructs focused code context packages for vulnerability candidates. 

Rather than passing an entire repository or massive source files to downstream LLM prompts, `ContextBuilder` aggregates precise context snippets (sink function, source function, enclosing class skeleton, caller/callee chain, REST endpoint mapping, architecture summary, configuration snippets, and related test fixtures) bounded by a strict, configurable character/token budget.

---

## 2. Implementation Details

### 2.1 Data Models & Classes
Created [harness/context_builder.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/context_builder.py) with the following structured classes:

| Class | Purpose |
| :--- | :--- |
| `ContextConfig` | Configuration settings (character budget, token multiplier, call depth limits, section caps, and feature toggles) |
| `ContextSection` | A single context snippet with label, file provenance, line range (`start_line`, `end_line`), content, and character count |
| `CandidateContext` | Complete context package for a candidate, providing serialization (`to_dict()`) and prompt text rendering (`to_prompt_text()`) |
| `ContextBuilder` | Main retrieval engine coordinating symbol index lookups, reconnaissance summary integration, and file reading |

### 2.2 Context Construction Pipeline
For each candidate vulnerability, `ContextBuilder` executes a multi-stage retrieval process:

1. **Sink Function**: Resolves the exact Java method containing the sink via `JavaSymbolIndex.get_method_at_line()` or symbol lookup.
2. **Enclosing Class Skeleton**: Extracts class declaration, annotations, and field declarations while omitting method bodies to preserve budget.
3. **Caller Chain**: Traverses caller edges up to `max_caller_callee_depth` (default: 2) to capture upstream callers.
4. **Callee Chain**: Traverses callee edges up to `max_caller_callee_depth` to capture downstream calls from the sink method.
5. **Source Function**: Identifies endpoint controller methods in the same class that receive untrusted HTTP input and call the sink method.
6. **Endpoint Metadata**: Resolves HTTP method, URL pattern, and Spring mapping annotations.
7. **Architecture Summary**: Integrates high-level module, endpoint, and pattern statistics from `reconnaissance.json`.
8. **Configuration Context**: Includes relevant Spring security configurations (`application.properties`/`.yml` and `@Configuration` classes).
9. **Test Fixtures**: Includes matching unit/integration test files (`*Test.java`, `*IT.java`) for reachability and evidence verification.

### 2.3 Budget Management & Provenance Safeguards
- **Character/Token Budgeting**: Defaults to 32,000 characters (~8,000 estimated tokens). Sections are added iteratively; if a section exceeds the remaining budget, it is truncated cleanly with a `[truncated to fit budget]` marker and noted in `warnings`.
- **Provenance Tracking**: Every section retains exact `file`, `start_line`, and `end_line` metadata, allowing downstream LLM prompts and validators to reference line-exact code locations.
- **Missing File Graceful Fallback**: If source files are missing on disk (e.g. synthetic test fixtures), `_read_method` and `_read_class_skeleton` fall back to metadata-driven code stubs instead of failing.

---

## 3. Key Design Decisions

1. **Symbol Index Integration**: Reuses `JavaSymbolIndex` (Task 2.2) static lookup methods (`lookup_callers`, `lookup_callees`, `get_method_at_line`, `get_class_at_line`) for fast, deterministic context resolution.
2. **Reconnaissance Map Integration**: Integrates `ReconnaissanceResult` (Task 2.1) data for architecture overview and category pattern matching without extra I/O.
3. **Class Skeletonization**: Truncates method bodies when building class context to avoid token bloat while keeping class field and annotation signatures intact.
4. **On-Demand File Reading & Caching**: Caches file lines in memory during context assembly to prevent duplicate disk reads across multi-section lookups.
5. **JSON & CLI Interfaces**: Supports programmatic batch retrieval (`build_contexts_batch`) and standalone CLI usage (`python3 -m harness.context_builder`).

---

## 4. Files Created / Modified

- **[harness/context_builder.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/context_builder.py)** — Main context retrieval implementation (~780 lines).
- **[harness/indexer.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/indexer.py)** — Added `load_index()` static method to deserialize `symbol_index.json` into dataclass models.
- **[tests/test_context_builder.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_context_builder.py)** — Unit and integration test suite (5 tests covering unit, budget enforcement, rendering, batching, and real WebGoat files).
- **[CONTEXT.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/CONTEXT.md)** — Updated with rule to always write report after implementing each task.
- **[reports/phase-2/task-2.3-context-retrieval.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/reports/phase-2/task-2.3-context-retrieval.md)** — Task completion report (this file).

---

## 5. Test Results

Unit and integration tests in [tests/test_context_builder.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_context_builder.py) and the entire suite were executed.

- **Total Test Suite**: 144 tests across all modules
- **Pass Rate**: 100% (144/144 passed)
- **Execution Time**: ~2.2 seconds

### Context Builder Test Breakdown:

| Test | Coverage |
| :--- | :--- |
| `test_build_context_basic` | Verifies sink, class, endpoint, and architecture sections assembly |
| `test_budget_exceeded_truncation` | Verifies strict character budget enforcement and warning generation |
| `test_to_prompt_text_rendering` | Verifies markdown/prompt rendering of section headers and code |
| `test_batch_context_building` | Verifies batch processing over multiple candidate dicts |
| `test_real_webgoat_candidate` | Integration test verifying context building on actual WebGoat SQLi candidates |

---

## 6. How to Verify / Test

To test context retrieval via CLI on a WebGoat file:

```bash
python3 -m harness.context_builder \
  --source webgoat/WebGoat-2025.3 \
  --index results/symbol_index.json \
  --recon results/reconnaissance.json \
  --file src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java \
  --line 30 \
  --category database
```

To run the unit test suite:

```bash
python3 -m unittest discover -s tests -v
```

---

## 7. Status & Conclusion

- **Status**: ✅ Complete
- **Conclusion**: The context retrieval module is fully operational. It combines symbol index lookups, reconnaissance summary data, and selective source code extraction into budget-constrained context packages ready for downstream LLM vulnerability analysis (Phase 6). All 144 unit and integration tests pass cleanly.
