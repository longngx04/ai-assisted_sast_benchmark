# Task 0.4 — Xác định dependency và generated code

| Attribute | Details |
| :--- | :--- |
| **Task ID** | Task 0.4 |
| **Title** | Xác định dependency và generated code |
| **Status** | ✅ Complete |
| **Phase** | Phase 0: WebGoat Ingestion, Environment Verification & Scope Baseline |
| **Date** | 2026-07-21 |

---

## 1. Objective

The objective of Task 0.4 is to establish a deterministic scope-filtering baseline that excludes build outputs, vendored dependencies, compiler binaries, and temporary tool metadata from security scanning. Crucially, the policy explicitly retains target unit and integration test suites (`**/src/test/**`) in scope, as WebGoat test files frequently contain local ground-truth evidence, reachability hints, and vulnerable component assertions.

---

## 2. Implementation Details

### 2.1 Central Exclusion Configuration ([configs/exclusions.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/configs/exclusions.json))
Created [configs/exclusions.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/configs/exclusions.json) containing 10 structured exclusion rules and 1 explicit inclusion directive:

| Pattern | Match Strategy | Category | Reason / Rationale |
| :--- | :--- | :--- | :--- |
| `**/.git/**` | `directory_segment` | `repository_metadata` | Git object and metadata files are not executable product source. |
| `**/.mvn/**` | `directory_segment` | `build_tooling` | Maven wrapper bootstrap code and binaries are build tooling. |
| `**/target/**` | `directory_segment` | `build_output` | Maven output duplicates source and contains generated or compiled artifacts. |
| `**/build/**` | `directory_segment` | `build_output` | Build output is generated and can duplicate product source. |
| `**/.gradle/**` | `directory_segment` | `build_cache` | Gradle cache data is not product source. |
| `**/node_modules/**` | `directory_segment` | `dependency` | Vendored JavaScript dependencies are outside the source-analysis scope. |
| `**/vendor/**` | `directory_segment` | `dependency` | Vendored third-party dependencies are outside the product-source scope. |
| `**/generated/**` | `directory_segment` | `generated_source` | Generated source is excluded unless an experiment explicitly opts in. |
| `**/out/**` | `directory_segment` | `build_output` | IDE and compiler output is generated from tracked source. |
| `**/*.class` | `suffix` | `compiled_binary` | Compiled JVM bytecode is not scanned as source code. |

#### Explicit Inclusion:
- **Pattern**: `**/src/test/**`
- **Reason**: Tests remain searchable because they can establish reachability, intended behavior, and local ground-truth evidence.

### 2.2 Policy Engine Engine ([harness/exclusions.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/exclusions.py))
Implemented [ExclusionPolicy](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/exclusions.py#L23) in Python using standard library `pathlib.PurePosixPath`:
- Supports three high-performance path matching strategies: `directory_segment` (segment matching in path parts), `suffix` (file extension matching), and `path_prefix` (directory path matching).
- Exposes `should_exclude(path)` to evaluate relative or absolute paths cleanly across Linux/Windows separators.
- Exposes `manifest_rules()` to seamlessly populate repository manifests with documented rule categories.

---

## 3. Files Created / Modified

- **[configs/exclusions.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/configs/exclusions.json)** — Central exclusion policy rule dictionary.
- **[harness/exclusions.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/exclusions.py)** — Exclusion engine class and path matching logic.
- **[tests/test_exclusions.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_exclusions.py)** — Unit test suite for exclusion matching rules.

---

## 4. Test Results

Unit test suite in [tests/test_exclusions.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_exclusions.py) was executed.

- **Total Tests**: 3 test methods
- **Pass Rate**: 100% (3/3 passed)

### Test Coverage Details:
1. `test_excludes_build_dependency_generated_and_class_files`: Verifies that target binaries, build output (`target/classes/App.class`), `.mvn`, `node_modules`, `vendor`, and `generated` paths are correctly excluded.
2. `test_keeps_product_and_test_source`: Confirms that both `src/main/java/example/App.java` and `src/test/java/example/AppTest.java` are kept in scope.
3. `test_each_rule_documents_its_reason`: Ensures every rule retains non-empty, explicit documentation rationale.

---

## 5. How to Verify / Test

To run the unit test suite for exclusion logic:

```bash
python3 -m unittest tests.test_exclusions -v
```

Expected unit test output:
```
test_each_rule_documents_its_reason (tests.test_exclusions.ExclusionPolicyTest.test_each_rule_documents_its_reason) ... ok
test_excludes_build_dependency_generated_and_class_files (tests.test_exclusions.ExclusionPolicyTest.test_excludes_build_dependency_generated_and_class_files) ... ok
test_keeps_product_and_test_source (tests.test_exclusions.ExclusionPolicyTest.test_keeps_product_and_test_source) ... ok

----------------------------------------------------------------------
Ran 3 tests in 0.001s

OK
```

---

## 6. Status & Conclusion

- **Status**: ✅ Complete
- **Conclusion**: Exclusion policy framework is fully defined, documented, tested, and integrated into the benchmark repository collection harness.
