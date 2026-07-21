import unittest
from pathlib import Path

from harness.exclusions import ExclusionPolicy


POLICY_PATH = Path(__file__).parents[1] / "configs/exclusions.json"


class ExclusionPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = ExclusionPolicy.from_file(POLICY_PATH)

    def test_excludes_build_dependency_generated_and_class_files(self):
        expected = [
            "target/classes/App.class",
            "module/build/generated/App.java",
            "frontend/node_modules/library/index.js",
            "vendor/dependency/File.java",
            "src/main/generated/Api.java",
            "out/production/App.class",
            ".mvn/wrapper/MavenWrapperDownloader.java",
        ]
        for path in expected:
            with self.subTest(path=path):
                self.assertTrue(self.policy.should_exclude(path))

    def test_keeps_product_and_test_source(self):
        self.assertFalse(self.policy.should_exclude("src/main/java/example/App.java"))
        self.assertFalse(self.policy.should_exclude("src/test/java/example/AppTest.java"))

    def test_each_rule_documents_its_reason(self):
        self.assertTrue(all(rule.reason.strip() for rule in self.policy.rules))


if __name__ == "__main__":
    unittest.main()
