"""Public design validation must ignore downloaded upstream build documents."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import validate_design


class DesignScopeTests(unittest.TestCase):
    def test_completed_and_open_acceptance_checkboxes_are_valid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "planning").mkdir()
            for mark in (" ", "x", "X"):
                data = {"milestones": [{"key": "M0", "title": "Scope", "description": "Evidence"}],
                        "issues": [{"key": "K01", "milestone": "M0", "priority": "P0", "phase": "Next",
                                    "title": "Boot", "labels": ["area:kernel"],
                                    "body": f"- [{mark}] Boot acceptance\n\nEvidence is retained.", "depends_on": []}]}
                (root / "planning/backlog.json").write_text(json.dumps(data))
                with self.subTest(mark=mark), patch.object(validate_design, "ROOT", root), \
                        patch.object(validate_design, "errors", []):
                    self.assertEqual(validate_design.validate_backlog(), (1, 1))
                    self.assertEqual(validate_design.errors, [])

    def test_plain_acceptance_text_still_requires_a_checkbox(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "planning").mkdir()
            data = {"milestones": [{"key": "M0", "title": "Scope", "description": "Evidence"}],
                    "issues": [{"key": "K01", "milestone": "M0", "priority": "P0", "phase": "Next",
                                "title": "Boot", "labels": ["area:kernel"],
                                "body": "Boot acceptance has evidence.", "depends_on": []}]}
            (root / "planning/backlog.json").write_text(json.dumps(data))
            with patch.object(validate_design, "ROOT", root), patch.object(validate_design, "errors", []):
                validate_design.validate_backlog()
                self.assertEqual(validate_design.errors, ["K01: acceptance checkboxes required"])

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
