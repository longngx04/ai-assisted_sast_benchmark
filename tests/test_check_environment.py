import tempfile
import unittest
from pathlib import Path

from scripts.check_environment import collect_environment


class EnvironmentCheckTest(unittest.TestCase):
    def test_can_collect_versions_without_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = collect_environment(Path(temporary), run_build=False, timeout=1)
        self.assertEqual(result["network_policy"], "offline; Maven invoked with -o")
        self.assertFalse(result["offline_build"]["attempted"])
        self.assertIn("python", result["tools"])
        self.assertTrue(result["tools"]["python"]["available"])


if __name__ == "__main__":
    unittest.main()
