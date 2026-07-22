"""Tests for harness.indexer — Micro-task 2.2 Java symbol index."""

import json
import os
import tempfile
import textwrap
import unittest
from pathlib import Path

from harness.exclusions import ExclusionPolicy
from harness.indexer import (
    JavaIndexer,
    JavaSymbolIndex,
    ClassInfo,
    MethodInfo,
    EndpointMapping,
    CallerCalleeEdge,
    run_indexing,
    _to_serializable,
)


# Resolve real WebGoat root
REPO_ROOT = Path(__file__).parents[1]
WEBGOAT_ROOT = REPO_ROOT / "webgoat" / "WebGoat-2025.3"
EXCLUSIONS_PATH = REPO_ROOT / "configs" / "exclusions.json"


# ---------------------------------------------------------------------------
# Synthetic fixture for unit tests
# ---------------------------------------------------------------------------

_FIXTURE_JAVA = textwrap.dedent("""\
    package com.example.demo;

    import java.sql.Connection;
    import java.sql.Statement;
    import static org.junit.Assert.*;

    @RestController
    @RequestMapping("/api/users")
    public class UserController extends BaseController implements Serializable {

        private final UserService userService;

        public UserController(UserService userService) {
            this.userService = userService;
        }

        @GetMapping("/list")
        @ResponseBody
        public List<User> listUsers() {
            return userService.findAll();
        }

        @PostMapping("/search")
        @ResponseBody
        public AttackResult searchUser(@RequestParam String username) {
            String query = "SELECT * FROM users WHERE name = '" + username + "'";
            Connection conn = dataSource.getConnection();
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            return buildResult(rs);
        }

        private AttackResult buildResult(ResultSet rs) {
            return AttackResult.success(this);
        }
    }

    @Service
    class UserService {

        public List<User> findAll() {
            return repository.findAll();
        }

        protected User findById(int id) {
            return repository.findById(id);
        }
    }

    interface UserRepository {
        List<User> findAll();
        User findById(int id);
    }
""")


class TestJavaIndexerUnit(unittest.TestCase):
    """Unit tests using a synthetic Java fixture."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        # Create a fake source tree
        src_dir = Path(cls.tmpdir) / "src" / "main" / "java" / "com" / "example" / "demo"
        src_dir.mkdir(parents=True)
        (src_dir / "UserController.java").write_text(_FIXTURE_JAVA, encoding="utf-8")

        cls.indexer = JavaIndexer(cls.tmpdir)
        cls.index = cls.indexer.build()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_indexes_at_least_one_file(self):
        self.assertGreater(self.index.indexed_files, 0)

    def test_finds_classes(self):
        names = [c.name for c in self.index.classes]
        self.assertIn("UserController", names)
        self.assertIn("UserService", names)

    def test_finds_interface(self):
        names_kinds = [(c.name, c.kind) for c in self.index.classes]
        self.assertIn(("UserRepository", "interface"), names_kinds)

    def test_class_package(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        self.assertEqual(uc.package, "com.example.demo")
        self.assertEqual(uc.qualified_name, "com.example.demo.UserController")

    def test_class_extends(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        self.assertEqual(uc.extends, "BaseController")

    def test_class_implements(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        self.assertIn("Serializable", uc.implements)

    def test_class_annotations(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        ann_names = [a.name for a in uc.annotations]
        self.assertIn("RestController", ann_names)
        self.assertIn("RequestMapping", ann_names)

    def test_finds_methods(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        method_names = [m.name for m in uc.methods]
        self.assertIn("listUsers", method_names)
        self.assertIn("searchUser", method_names)
        self.assertIn("buildResult", method_names)

    def test_method_visibility(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        search = [m for m in uc.methods if m.name == "searchUser"][0]
        self.assertEqual(search.visibility, "public")
        build = [m for m in uc.methods if m.name == "buildResult"][0]
        self.assertEqual(build.visibility, "private")

    def test_method_has_parameters(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        search = [m for m in uc.methods if m.name == "searchUser"][0]
        self.assertIn("username", search.parameters)

    def test_endpoint_mapping_get(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        list_m = [m for m in uc.methods if m.name == "listUsers"][0]
        self.assertIsNotNone(list_m.endpoint)
        self.assertEqual(list_m.endpoint.http_method, "GET")
        self.assertIn("/list", list_m.endpoint.path)

    def test_endpoint_mapping_post(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        search = [m for m in uc.methods if m.name == "searchUser"][0]
        self.assertIsNotNone(search.endpoint)
        self.assertEqual(search.endpoint.http_method, "POST")
        self.assertIn("/search", search.endpoint.path)

    def test_endpoint_class_base_path(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        list_m = [m for m in uc.methods if m.name == "listUsers"][0]
        # Should combine class-level /api/users with method-level /list
        self.assertIn("/api/users", list_m.endpoint.path)

    def test_method_calls_extracted(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        search = [m for m in uc.methods if m.name == "searchUser"][0]
        # Should detect calls like getConnection, createStatement, executeQuery
        self.assertIn("getConnection", search.calls)
        self.assertIn("createStatement", search.calls)
        self.assertIn("executeQuery", search.calls)
        self.assertIn("buildResult", search.calls)

    def test_caller_callee_edges(self):
        edges = self.index.caller_callee_edges
        self.assertGreater(len(edges), 0)
        # searchUser should call buildResult
        search_edges = [
            e for e in edges
            if e.caller_method == "searchUser" and e.callee_method == "buildResult"
        ]
        self.assertEqual(len(search_edges), 1)

    def test_imports_extracted(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        import_stmts = [i.statement for i in uc.imports]
        self.assertIn("java.sql.Connection", import_stmts)
        self.assertIn("java.sql.Statement", import_stmts)

    def test_static_import(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        static_imports = [i for i in uc.imports if i.is_static]
        self.assertGreater(len(static_imports), 0)

    def test_wildcard_import(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        wildcard_imports = [i for i in uc.imports if i.is_wildcard]
        self.assertGreater(len(wildcard_imports), 0)

    def test_method_line_ranges(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        for m in uc.methods:
            self.assertGreater(m.start_line, 0)
            self.assertGreaterEqual(m.end_line, m.start_line)

    def test_class_line_ranges(self):
        for c in self.index.classes:
            self.assertGreater(c.start_line, 0)
            self.assertGreaterEqual(c.end_line, c.start_line)

    def test_summary_populated(self):
        s = self.index.summary
        self.assertGreater(s["total_classes"], 0)
        self.assertGreater(s["total_methods"], 0)
        self.assertGreater(s["total_endpoints"], 0)
        self.assertGreater(s["unique_packages"], 0)

    def test_json_serializable(self):
        payload = _to_serializable(self.index)
        text = json.dumps(payload, indent=2)
        parsed = json.loads(text)
        self.assertIn("classes", parsed)
        self.assertIn("summary", parsed)
        self.assertIn("caller_callee_edges", parsed)

    def test_save_creates_file(self):
        with tempfile.TemporaryDirectory() as outdir:
            path = self.indexer.save(self.index, outdir)
            self.assertTrue(path.exists())
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("classes", data)


class TestLookupAPIs(unittest.TestCase):
    """Test the static lookup helper methods."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        src_dir = Path(cls.tmpdir) / "src"
        src_dir.mkdir()
        (src_dir / "Demo.java").write_text(_FIXTURE_JAVA, encoding="utf-8")
        cls.indexer = JavaIndexer(cls.tmpdir)
        cls.index = cls.indexer.build()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_lookup_class_by_name(self):
        results = JavaIndexer.lookup_class(self.index, "UserController")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].name, "UserController")

    def test_lookup_class_by_qualified_name(self):
        results = JavaIndexer.lookup_class(self.index, "com.example.demo.UserController")
        self.assertEqual(len(results), 1)

    def test_lookup_method(self):
        results = JavaIndexer.lookup_method(self.index, "searchUser")
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0].name, "searchUser")

    def test_lookup_method_with_class_filter(self):
        results = JavaIndexer.lookup_method(
            self.index, "searchUser", class_name="UserController"
        )
        self.assertEqual(len(results), 1)

        # Non-matching class
        results = JavaIndexer.lookup_method(
            self.index, "searchUser", class_name="UserService"
        )
        self.assertEqual(len(results), 0)

    def test_lookup_callers(self):
        callers = JavaIndexer.lookup_callers(self.index, "buildResult")
        self.assertGreater(len(callers), 0)
        caller_methods = [e.caller_method for e in callers]
        self.assertIn("searchUser", caller_methods)

    def test_lookup_callees(self):
        callees = JavaIndexer.lookup_callees(
            self.index, "UserController", "searchUser"
        )
        callee_names = [e.callee_method for e in callees]
        self.assertIn("buildResult", callee_names)

    def test_lookup_endpoints(self):
        results = JavaIndexer.lookup_endpoints(self.index)
        self.assertGreater(len(results), 0)

    def test_lookup_endpoints_by_path(self):
        results = JavaIndexer.lookup_endpoints(self.index, path_substring="/search")
        self.assertEqual(len(results), 1)
        _, method = results[0]
        self.assertEqual(method.name, "searchUser")

    def test_lookup_endpoints_by_method(self):
        results = JavaIndexer.lookup_endpoints(self.index, http_method="POST")
        self.assertGreater(len(results), 0)

    def test_get_methods_in_file(self):
        file_path = self.index.classes[0].file
        methods = JavaIndexer.get_methods_in_file(self.index, file_path)
        self.assertGreater(len(methods), 0)

    def test_get_method_at_line(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        search = [m for m in uc.methods if m.name == "searchUser"][0]
        result = JavaIndexer.get_method_at_line(
            self.index, uc.file, search.start_line
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "searchUser")

    def test_get_class_at_line(self):
        uc = [c for c in self.index.classes if c.name == "UserController"][0]
        result = JavaIndexer.get_class_at_line(
            self.index, uc.file, uc.start_line + 1
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "UserController")


# ---------------------------------------------------------------------------
# Integration tests against real WebGoat
# ---------------------------------------------------------------------------

@unittest.skipUnless(WEBGOAT_ROOT.is_dir(), "WebGoat source not available")
class TestJavaIndexerWebGoat(unittest.TestCase):
    """Integration tests that run against the real WebGoat source."""

    @classmethod
    def setUpClass(cls):
        policy = ExclusionPolicy.from_file(EXCLUSIONS_PATH)
        cls.indexer = JavaIndexer(WEBGOAT_ROOT, exclusion_policy=policy)
        cls.index = cls.indexer.build()

    def test_indexes_java_files(self):
        self.assertGreater(self.index.indexed_files, 0)
        self.assertGreater(self.index.total_java_files, 0)

    def test_finds_multiple_classes(self):
        self.assertGreater(len(self.index.classes), 10)

    def test_finds_sql_injection_classes(self):
        names = [c.name for c in self.index.classes]
        # Should find at least one SQL injection related class
        sqli_classes = [n for n in names if "sql" in n.lower() or "injection" in n.lower()]
        self.assertGreater(len(sqli_classes), 0, "Should find SQL injection classes")

    def test_finds_methods(self):
        total_methods = sum(len(c.methods) for c in self.index.classes)
        self.assertGreater(total_methods, 0)

    def test_finds_endpoints(self):
        total_endpoints = sum(
            1 for c in self.index.classes for m in c.methods if m.endpoint
        )
        self.assertGreater(total_endpoints, 0)

    def test_finds_packages(self):
        packages = {c.package for c in self.index.classes}
        self.assertGreater(len(packages), 1)
        # Should find the main WebGoat package hierarchy
        has_webgoat = any("webgoat" in p for p in packages)
        self.assertTrue(has_webgoat, "Should find webgoat packages")

    def test_finds_caller_callee_edges(self):
        self.assertGreater(len(self.index.caller_callee_edges), 0)

    def test_finds_imports(self):
        total_imports = sum(len(c.imports) for c in self.index.classes)
        self.assertGreater(total_imports, 0)

    def test_finds_controllers(self):
        controllers = [
            c for c in self.index.classes
            if any(a.name in ("RestController", "Controller") for a in c.annotations)
        ]
        self.assertGreater(len(controllers), 0)

    def test_excludes_target_directory(self):
        for c in self.index.classes:
            self.assertNotIn("/target/", c.file, f"Excluded path leaked: {c.file}")

    def test_class_line_ranges_valid(self):
        for c in self.index.classes:
            self.assertGreater(c.start_line, 0, f"Invalid start_line for {c.name}")
            self.assertGreaterEqual(
                c.end_line, c.start_line,
                f"end_line < start_line for {c.name}",
            )

    def test_method_line_ranges_valid(self):
        for c in self.index.classes:
            for m in c.methods:
                self.assertGreater(
                    m.start_line, 0,
                    f"Invalid start_line for {c.name}.{m.name}",
                )
                self.assertGreaterEqual(
                    m.end_line, m.start_line,
                    f"end_line < start_line for {c.name}.{m.name}",
                )

    def test_result_is_json_serializable(self):
        payload = _to_serializable(self.index)
        text = json.dumps(payload, indent=2)
        parsed = json.loads(text)
        self.assertIn("classes", parsed)
        self.assertIn("caller_callee_edges", parsed)
        self.assertIn("summary", parsed)

    def test_summary_populated(self):
        s = self.index.summary
        self.assertGreater(s["total_classes"], 0)
        self.assertGreater(s["total_methods"], 0)
        self.assertGreater(s["unique_packages"], 0)

    def test_save_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.indexer.save(self.index, tmpdir)
            self.assertTrue(path.exists())
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("classes", data)
            self.assertGreater(len(data["classes"]), 0)

    def test_lookup_sql_injection_endpoint(self):
        """Should be able to find the SQL injection assignment endpoint."""
        results = JavaIndexer.lookup_endpoints(
            self.index, path_substring="SqlInjection"
        )
        self.assertGreater(
            len(results), 0,
            "Should find SQL injection endpoints",
        )


@unittest.skipUnless(WEBGOAT_ROOT.is_dir(), "WebGoat source not available")
class TestRunIndexingConvenience(unittest.TestCase):
    """Test the run_indexing convenience function."""

    def test_run_indexing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            index = run_indexing(
                str(WEBGOAT_ROOT),
                tmpdir,
                str(EXCLUSIONS_PATH),
            )
            self.assertGreater(index.indexed_files, 0)
            self.assertGreater(len(index.classes), 0)
            # Check output file exists
            index_file = Path(tmpdir) / "symbol_index.json"
            self.assertTrue(index_file.exists())


if __name__ == "__main__":
    unittest.main()
