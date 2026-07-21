import json
import tempfile
import unittest
from pathlib import Path

from scripts.collect_repository_manifest import collect_manifest


class RepositoryManifestTest(unittest.TestCase):
    def test_collects_source_counts_paths_and_maven_project(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pom.xml").write_text(
                """<project xmlns=\"http://maven.apache.org/POM/4.0.0\">
                  <parent><artifactId>spring-boot-starter-parent</artifactId></parent>
                  <artifactId>fixture-app</artifactId>
                  <dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies>
                </project>""",
                encoding="utf-8",
            )
            source = root / "src/main/java/example/App.java"
            source.parent.mkdir(parents=True)
            source.write_text("class App {\n}\n", encoding="utf-8")
            test = root / "src/test/java/example/AppTest.java"
            test.parent.mkdir(parents=True)
            test.write_text("class AppTest {}\n", encoding="utf-8")
            (root / "target/classes/Generated.java").parent.mkdir(parents=True)
            (root / "target/classes/Generated.java").write_text("ignored\n", encoding="utf-8")

            manifest = collect_manifest(root)

            self.assertEqual(manifest["source"]["java_file_count"], 2)
            self.assertEqual(manifest["paths"]["source"], ["src/main"])
            self.assertEqual(manifest["paths"]["tests"], ["src/test"])
            self.assertEqual(manifest["maven_modules"], [{"path": ".", "artifact_id": "fixture-app"}])
            self.assertEqual(manifest["revision"], None)
            self.assertTrue(any(rule["pattern"] == "**/target/**" for rule in manifest["exclusions"]))
            self.assertTrue(any(item["pattern"] == "**/src/test/**" for item in manifest["explicit_inclusions"]))

    def test_manifest_is_json_serializable(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = collect_manifest(Path(temporary))
            json.dumps(manifest)
            self.assertIsNone(manifest["language"]["primary"])
            self.assertTrue(manifest["warnings"])


if __name__ == "__main__":
    unittest.main()
