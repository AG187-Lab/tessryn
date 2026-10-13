"""CI publishes the declared K01 files without private sidecars or future runs."""

import json
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_kernel import CASES, HIGH_PROFILES


def configured_paths() -> list[str]:
    workflow = (ROOT / ".github/workflows/k01.yml").read_text()
    blocks = re.findall(r"(?m)^          path: \|\n((?:            [^\n]+\n)+)", workflow)
    if len(blocks) != 1:
        raise AssertionError("expected one literal upload-artifact path list")
    return [line.strip() for line in blocks[0].splitlines()]


def recorded_public_inventory() -> set[str]:
    """Map the real retained manifests/results to the workflow's output names."""
    evidence = ROOT / "evidence/k01-aws-preparation"
    inventory = set()
    for profile, output in (("baseline", "kernel"), ("high", "high-kernel"), ("headless", "aws")):
        manifest = json.loads((evidence / profile / "manifest-a.json").read_text())
        prefix = f"build/{output}-a"
        inventory.update((f"{prefix}/manifest.json", f"build/{output}-b/manifest.json"))
        for row in manifest["artifacts"]:
            # Keep the existing 1 GiB normal AWS disk without uploading all six.
            if profile == "headless" and row["path"].endswith("/boot.img") and row["case"] != "normal":
                continue
            inventory.add(f"{prefix}/{row['path']}")
            if row["path"].endswith("/BOOTX64.EFI"):
                inventory.add(f"{prefix}/{PurePosixPath(row['path']).parent}/build.log")
        for row in manifest["notices"]:
            inventory.add(f"{prefix}/{row['path']}")
        for row in manifest.get("snapshot_input_plans", []):
            inventory.add(f"{prefix}/{row['path']}")

        directories = [directory for directory in (evidence / profile).iterdir()
                       if directory.is_dir() and (directory / "result.json").is_file()]
        expected_cases = set(HIGH_PROFILES) if profile == "high" else set(CASES)
        if profile == "baseline":
            expected_cases.add("iso")
        if {directory.name for directory in directories} != expected_cases:
            raise AssertionError("retained executions differ from the declared CI profiles")
        for directory in directories:
            run = f"build/aws-{directory.name}" if profile == "headless" else (
                f"build/k01-high-{directory.name}" if profile == "high" else f"build/k01-{directory.name}")
            result = json.loads((directory / "result.json").read_text())
            inventory.add(f"{run}/result.json")
            inventory.update(f"{run}/{row['path']}" for row in result["logs"])

    display = json.loads((evidence / "display/result.json").read_text())
    inventory.add("build/k01-display/result.json")
    inventory.update(f"build/k01-display/{row['path']}" for row in display["logs"])
    inventory.add(f"build/k01-display/{display['screenshot']['path']}")
    inventory.update(("build/k01-verification.json", "build/k01-high-verification.json",
                      "build/aws-verification.json"))
    return inventory


def selected_files(root: Path, patterns: list[str]) -> set[str]:
    selected = set()
    for pattern in patterns:
        for path in root.glob(pattern):
            # upload-artifact recursively publishes a matched directory.
            files = path.rglob("*") if path.is_dir() else [path]
            selected.update(file.relative_to(root).as_posix() for file in files if file.is_file())
    return selected


class K01ArtifactAllowlistTests(unittest.TestCase):
    def test_configured_files_cover_the_retained_manifest_and_execution_inventory(self):
        self.assertEqual(set(configured_paths()), recorded_public_inventory())

    def test_every_entry_is_a_unique_exact_filename(self):
        paths = configured_paths()
        self.assertEqual(len(paths), len(set(paths)))
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(path.startswith("build/"))
                self.assertNotIn("..", PurePosixPath(path).parts)
                self.assertFalse(any(character in path for character in "*?[]!"))
                self.assertFalse(path.endswith("/"))

    def test_private_sidecars_and_new_run_directories_are_not_uploaded(self):
        public = recorded_public_inventory()
        private = {
            "build/k01-normal/private-capture.json",
            "build/k01-high-image-normal/private/result.json",
            "build/k01-display/inspection-private.json",
            "build/k01-display/capture-index.json",
            "build/k01-native-private/result.json",
            "build/aws-native-private/result.json",
            "build/aws-native-private/stdout.log",
            "build/aws-normal/owner-receipt.json",
            "build/aws-normal/private/result.json",
            "build/aws-a/private/BOOTX64.EFI",
            "build/aws-a/private/build.log",
            "build/kernel-a/private/boot.img",
            "build/high-kernel-a/private/build.log",
            "build/kernel-a/notices/private-owner-note.txt",
            "build/aws-a/notices/private-owner-note.txt",
            "build/uefi/firmware/edk2-x86_64-code.fd",
            "build/uefi/firmware/edk2-i386-vars.fd",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in public | private:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture")
            selected = selected_files(root, configured_paths())
            self.assertEqual(selected, public)
            self.assertFalse(selected & private)


if __name__ == "__main__":
    unittest.main()
