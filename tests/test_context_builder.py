"""Unit and integration tests for harness.context_builder (Micro-task 2.3)."""

import json
import unittest
from pathlib import Path

from harness.context_builder import (
    CandidateContext,
    ContextBuilder,
    ContextConfig,
    ContextSection,
    build_candidate_context,
)
from harness.indexer import (
    AnnotationInfo,
    CallerCalleeEdge,
    ClassInfo,
    EndpointMapping,
    ImportInfo,
    JavaIndexer,
    JavaSymbolIndex,
    MethodInfo,
)


class TestContextBuilderUnit(unittest.TestCase):
    """Unit tests using a synthetic in-memory JavaSymbolIndex."""

    def setUp(self) -> None:
        self.webgoat_root = Path("webgoat/WebGoat-2025.3").resolve()

        # Build synthetic index
        method1 = MethodInfo(
            name="searchUser",
            class_name="SqlInjectionLesson",
            file="src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java",
            start_line=10,
            end_line=25,
            visibility="public",
            return_type="AttackResult",
            parameters="String username",
            annotations=[AnnotationInfo("PostMapping", '@PostMapping("/sqli/search")', 9)],
            endpoint=EndpointMapping("POST", "/sqli/search", "@PostMapping"),
            calls=["executeQuery", "sanitizer"],
        )
        method2 = MethodInfo(
            name="executeQuery",
            class_name="SqlInjectionLesson",
            file="src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java",
            start_line=27,
            end_line=35,
            visibility="private",
            return_type="ResultSet",
            parameters="String query",
            annotations=[],
            endpoint=None,
            calls=[],
        )
        cls = ClassInfo(
            kind="class",
            name="SqlInjectionLesson",
            qualified_name="org.owasp.webgoat.sqli.SqlInjectionLesson",
            package="org.owasp.webgoat.sqli",
            file="src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java",
            start_line=5,
            end_line=40,
            visibility="public",
            annotations=[AnnotationInfo("RestController", "@RestController", 4)],
            extends=None,
            implements=[],
            methods=[method1, method2],
            imports=[],
        )
        edge = CallerCalleeEdge(
            caller_class="SqlInjectionLesson",
            caller_method="searchUser",
            callee_method="executeQuery",
            file="src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java",
            caller_line=15,
        )
        self.index = JavaSymbolIndex(
            generated_at="2026-07-22T00:00:00Z",
            webgoat_root=str(self.webgoat_root),
            total_java_files=1,
            indexed_files=1,
            excluded_files=0,
            classes=[cls],
            caller_callee_edges=[edge],
            summary={"total_classes": 1, "total_methods": 2},
        )

        self.recon = {
            "summary": {"total_components": 1, "total_endpoints": 1, "total_security_patterns": 5},
            "lesson_modules": [{"name": "sqlinjection"}],
            "security_patterns": {
                "database": [{"file": "src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java"}]
            },
        }

    def test_build_context_basic(self) -> None:
        cfg = ContextConfig(budget_chars=5000, include_config=False, include_tests=False)
        builder = ContextBuilder(
            webgoat_root=self.webgoat_root,
            index=self.index,
            recon=self.recon,
            config=cfg,
        )
        ctx = builder.build_context(
            candidate_id="cand-001",
            file="src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java",
            line=15,
            symbol="searchUser",
            category="database",
        )

        self.assertEqual(ctx.candidate_id, "cand-001")
        self.assertEqual(ctx.file, "src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java")
        self.assertEqual(ctx.line, 15)
        self.assertFalse(ctx.budget_exceeded)
        self.assertGreater(ctx.total_chars, 0)
        self.assertGreater(ctx.total_estimated_tokens, 0)

        # Check section labels
        labels = [s.label for s in ctx.sections]
        self.assertIn("sink_function", labels)
        self.assertIn("enclosing_class", labels)
        self.assertIn("endpoint_info", labels)
        self.assertIn("architecture_summary", labels)

    def test_budget_exceeded_truncation(self) -> None:
        # Extremely small budget to force truncation / skipping
        cfg = ContextConfig(budget_chars=300)
        builder = ContextBuilder(
            webgoat_root=self.webgoat_root,
            index=self.index,
            recon=self.recon,
            config=cfg,
        )
        ctx = builder.build_context(
            candidate_id="cand-small-budget",
            file="src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java",
            line=15,
            symbol="searchUser",
            category="database",
        )

        self.assertTrue(ctx.budget_exceeded or len(ctx.warnings) > 0)
        self.assertLessEqual(ctx.total_chars, 500)  # capped close to budget

    def test_to_prompt_text_rendering(self) -> None:
        cfg = ContextConfig(budget_chars=5000, include_config=False, include_tests=False)
        ctx = build_candidate_context(
            webgoat_root=self.webgoat_root,
            index=self.index,
            candidate_id="cand-render",
            file="src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java",
            line=15,
            symbol="searchUser",
            category="database",
            recon=self.recon,
            config=cfg,
        )

        text = ctx.to_prompt_text()
        self.assertIn("=== sink_function ===", text)
        self.assertIn("SqlInjectionLesson.java", text)

    def test_batch_context_building(self) -> None:
        builder = ContextBuilder(
            webgoat_root=self.webgoat_root,
            index=self.index,
            recon=self.recon,
        )
        candidates = [
            {
                "candidate_id": "c1",
                "file": "src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java",
                "line": 15,
                "symbol": "searchUser",
                "category": "database",
            },
            {
                "candidate_id": "c2",
                "file": "src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java",
                "line": 30,
                "symbol": "executeQuery",
                "category": "database",
            },
        ]
        results = builder.build_contexts_batch(candidates)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].candidate_id, "c1")
        self.assertEqual(results[1].candidate_id, "c2")


class TestContextBuilderWebGoat(unittest.TestCase):
    """Integration test against actual WebGoat symbol index and recon files."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.webgoat_root = Path("webgoat/WebGoat-2025.3").resolve()
        cls.index_file = Path("results/symbol_index.json")
        cls.recon_file = Path("results/reconnaissance.json")

        if cls.index_file.exists():
            with open(cls.index_file, "r", encoding="utf-8") as f:
                raw_index = json.load(f)
            cls.index = JavaIndexer.load_index(raw_index)
        else:
            cls.index = None

        if cls.recon_file.exists():
            with open(cls.recon_file, "r", encoding="utf-8") as f:
                cls.recon = json.load(f)
        else:
            cls.recon = None

    def test_real_webgoat_candidate(self) -> None:
        if not self.index or not self.recon:
            self.skipTest("symbol_index.json or reconnaissance.json missing")

        # Pick a real file from index
        target_file = None
        for c in self.index.classes:
            if "sqli" in c.file.lower() and c.methods:
                target_file = c.file
                target_method = c.methods[0]
                break

        if not target_file:
            self.skipTest("No suitable SQLi file found in symbol_index.json")

        cfg = ContextConfig(budget_chars=16000)
        builder = ContextBuilder(
            webgoat_root=self.webgoat_root,
            index=self.index,
            recon=self.recon,
            config=cfg,
        )

        ctx = builder.build_context(
            candidate_id="real-webgoat-cand-1",
            file=target_file,
            line=target_method.start_line,
            symbol=target_method.name,
            category="database",
        )

        self.assertEqual(ctx.candidate_id, "real-webgoat-cand-1")
        self.assertEqual(ctx.file, target_file)
        self.assertGreater(len(ctx.sections), 0)
        self.assertLessEqual(ctx.total_chars, 16000)


if __name__ == "__main__":
    unittest.main()
