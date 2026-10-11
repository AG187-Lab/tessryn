"""Public design validation must ignore downloaded upstream build documents."""

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import validate_design


class DesignScopeTests(unittest.TestCase):
    def test_generated_documents_are_excluded_but_public_documents_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in ("build/download", "target", "artifacts", "design"):
                (root / directory).mkdir(parents=True)
                (root / directory / "test.md").write_text("[broken](missing.md)")
            with patch.object(validate_design, "ROOT", root), patch.object(validate_design, "errors", []):
                self.assertEqual(validate_design.validate_documents(), 1)
                self.assertEqual(len(validate_design.errors), 1)
                self.assertIn("design/test.md", validate_design.errors[0])


if __name__ == "__main__":
    unittest.main()
