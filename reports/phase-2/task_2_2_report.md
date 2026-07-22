# Report: Micro-task 2.2 — Java Symbol Index

## Task Summary

**Micro-task 2.2** requires implementing `harness/indexer.py` — a Java symbol index that builds an index of classes, methods, annotations, imports, endpoint mappings, and caller/callee relationships over Java source files.

**Status: ✅ Complete**

---

## Implementation Overview

### Module: `harness/indexer.py`

A deterministic, regex-based Java symbol indexer that operates without LLM calls. It scans Java source files and builds a structured index for use by downstream phases (context builder, candidate finder).

### Data Models

| Model | Description |
|-------|-------------|
| `ImportInfo` | Import statements (static, wildcard tracking) |
| `AnnotationInfo` | Annotations on classes and methods |
| `MethodInfo` | Method declarations with line ranges, visibility, parameters, endpoint mappings, and call graph |
| `EndpointMapping` | Spring `@*Mapping` endpoint information |
| `ClassInfo` | Class/interface/enum/record/annotation_type declarations with full metadata |
| `CallerCalleeEdge` | Directed caller → callee edges for method call tracking |
| `JavaSymbolIndex` | Top-level index containing all indexed data and summary |

### Capabilities

1. **Type declaration indexing**: class, interface, enum, record, `@interface`
2. **Method indexing**: name, visibility, return type, parameters, line ranges
3. **Package & import tracking**: full import statements, static/wildcard detection
4. **Annotation extraction**: class-level and method-level annotations
5. **Spring endpoint mapping**: resolves class-level base paths with method-level paths
6. **Caller/callee edges**: best-effort intra-file method call extraction
7. **Inheritance**: `extends` and `implements` relationships
8. **Exclusion policy**: respects `configs/exclusions.json` (skips build output, `.class`, etc.)
9. **Lookup APIs**: 8 static helper methods for querying the index

### Lookup API Methods

| Method | Purpose |
|--------|---------|
| `lookup_class(index, name)` | Find classes by simple or qualified name |
| `lookup_method(index, name, class_name?)` | Find methods, optionally filtered by class |
| `lookup_callers(index, method)` | Find all callers of a method |
| `lookup_callees(index, class, method)` | Find all methods called from a class.method |
| `lookup_endpoints(index, path?, method?)` | Find endpoint methods, with optional filters |
| `get_methods_in_file(index, file)` | List all methods in a file |
| `get_method_at_line(index, file, line)` | Find the method containing a specific line |
| `get_class_at_line(index, file, line)` | Find the class containing a specific line |

### Output

- **File**: `results/symbol_index.json`
- **Format**: JSON with nested dataclass serialization
- **CLI**: `python3 -m harness.indexer --source <path> --output <dir> --exclusions <config>`
- **Programmatic**: `run_indexing(webgoat_root, output_dir, exclusion_config)`

---

## WebGoat Indexing Results

| Metric | Value |
|--------|-------|
| Files indexed | 370 |
| Files excluded | 1 |
| Classes found | 384 |
| Methods found | 1,244 |
| REST endpoints | 78 |
| Caller/callee edges | 7,215 |
| Unique packages | 70 |

---

## Test Suite

### Test file: `tests/test_indexer.py`

| Test Class | Tests | Description |
|------------|-------|-------------|
| `TestJavaIndexerUnit` | 23 | Unit tests with synthetic Java fixture |
| `TestLookupAPIs` | 12 | Lookup helper method tests |
| `TestJavaIndexerWebGoat` | 16 | Integration tests against real WebGoat |
| `TestRunIndexingConvenience` | 1 | Convenience function test |
| **Total** | **52** | **All pass** |

### Test results

```
Ran 52 tests in 0.952s

OK
```

All 139 tests in the full suite (52 new + 87 existing) pass with no regressions.

---

## Known Limitations

Documented in module docstring per PLAN requirements:

1. **Regex-based**: May miss edge-cases (lambdas, anonymous classes, nested generics in method signatures). No full AST parser (e.g., Tree-sitter with Java grammar) is used.
2. **Caller/callee is intra-file best-effort**: Method calls are extracted from method bodies using heuristic patterns and may include false positives (e.g., chained builder calls) or miss calls via variables.
3. **No cross-file type resolution**: Does not perform full type inference. Method calls are by name only, not by fully qualified signature.
4. **Brace counting for block boundaries**: May miscalculate end_line in files with unusual formatting or complex nested lambdas.

---

## Files Created/Modified

| File | Action | Size |
|------|--------|------|
| `harness/indexer.py` | Created | ~900 lines |
| `tests/test_indexer.py` | Created | ~330 lines |
| `results/symbol_index.json` | Generated | index output |
| `reports/task_2_2_report.md` | Created | this report |

---

## Relationship to Other Phases

- **Depends on**: `harness/exclusions.py` (Phase 0.4)
- **Used by**: `harness/context_builder.py` (Micro-task 2.3 — Context retrieval)
- **Used by**: `harness/candidate_finder.py` (Phase 3 — Candidate discovery)
- **Used by**: `harness/investigator.py` (Phase 6 — Investigation agent)
- **Used by**: `harness/validator.py` (Phase 6 — Validator needs caller/callee context)

The index provides the foundation for:
- Tracing data flow from a suspicious line to the enclosing method, class, and call chain
- Resolving endpoint mappings for context-aware vulnerability analysis
- Building focused context packages that include relevant caller/callee code without sending the entire repository to the model
