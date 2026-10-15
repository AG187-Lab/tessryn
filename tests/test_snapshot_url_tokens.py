"""Synthetic opaque-token regression fixtures; these are not AWS evidence."""

import copy
from pathlib import Path
import sys
import types
import unittest


# Reuse the public synthetic upload/readback chain without importing its tests
# into this module's discovery namespace or relying on a local checkout path.
_fixture_path = Path(__file__).with_name("test_aws_native_snapshot.py")
_fixture = types.ModuleType("snapshot_url_token_fixture")
_fixture.__file__ = str(_fixture_path)
sys.modules[_fixture.__name__] = _fixture
exec(compile(_fixture_path.read_bytes(), str(_fixture_path), "exec"), _fixture.__dict__)


class SnapshotUrlTokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _fixture.AwsNativeSnapshotTests.setUpClass()

    def setUp(self):
        self.chain = _fixture.AwsNativeSnapshotTests()
        self.chain.setUp()

    def block_token(self, index, value):
        for alias in self.chain.spec["list_pages"]:
            for row in self.chain.records[alias].response["Blocks"]:
                if row["BlockIndex"] == index:
                    row["BlockToken"] = value
        self.chain.records["get-" + str(index)].request["BlockToken"] = value

    def page_token(self, first, second, value):
        self.chain.records[first].response["NextToken"] = value
        self.chain.records[second].request["NextToken"] = value

    def url_tokens(self):
        for index in _fixture.INDICES:
            token = ("synthetic_opaque-" + str(index) + "A" * 95)[:95]
            self.block_token(index, token)
        self.page_token("list-0", "list-1", "synthetic_page-one_")
        self.page_token("list-1", "list-2", "synthetic_page-two_")

    def rejected(self, reason):
        with self.assertRaisesRegex(ValueError, reason):
            self.chain.verify()
        self.assertEqual(self.chain.captures.read_sizes, [])

    def test_url_safe_opaque_tokens_bind_list_get_and_logical_readback(self):
        self.url_tokens()
        original_data = self.chain.files.copy()
        original_checksums = {alias: copy.deepcopy(record.response)
                              for alias, record in self.chain.records.items()
                              if alias.startswith(("put-", "get-"))}
        result = self.chain.verify()
        self.assertEqual(result["block_indices"], _fixture.INDICES)
        self.assertEqual(result["reconstructed_sha256"], self.chain.disk["sha256"])
        self.assertEqual((result["upload_count"], result["list_page_count"],
                          result["readback_count"]), (5, 3, 5))
        self.assertEqual(self.chain.captures.read_sizes,
                         [_fixture.snapshot.BLOCK_SIZE_BYTES] * 5)
        self.assertEqual(self.chain.files, original_data)
        self.assertEqual({alias: record.response for alias, record in self.chain.records.items()
                          if alias.startswith(("put-", "get-"))}, original_checksums)
        for alias in ("list-1", "list-2"):
            for row in self.chain.records[alias].response["Blocks"]:
                self.assertEqual(len(row["BlockToken"]), 95)
                self.assertIn("-", row["BlockToken"])
                self.assertIn("_", row["BlockToken"])
                self.assertEqual(self.chain.records["get-" + str(row["BlockIndex"])].request[
                    "BlockToken"], row["BlockToken"])
        self.assertNotIn("qualified", result)
        self.assertNotIn("status", result)

    def test_standard_base64_characters_still_pass_unchanged(self):
        for index in _fixture.INDICES:
            self.block_token(index, "Synthetic09+/=" + str(index))
        self.page_token("list-0", "list-1", "Synthetic09+/=first")
        self.page_token("list-1", "list-2", "Synthetic09+/=second")
        self.assertEqual(self.chain.verify()["reconstructed_sha256"], self.chain.disk["sha256"])

    def test_one_and_256_character_opaque_token_bounds(self):
        for value in ("_", "-" + "A" * 254 + "_"):
            with self.subTest(length=len(value)):
                self.chain.setUp()
                for index in _fixture.INDICES:
                    self.block_token(index, value)
                self.page_token("list-0", "list-1", value)
                self.page_token("list-1", "list-2", "A" if len(value) == 1 else "B" * 256)
                self.assertEqual(self.chain.verify()["readback_count"], 5)

    def test_other_punctuation_controls_space_unicode_and_length_rejected(self):
        invalid = ["", "A" * 257, "opaque.token", "opaque:token", "opaque?token",
                   "opaque\\token", "opaque token", "opaque\t", "opaque\n", "opaque\r",
                   "opaque\x00", "opaque\x7f", "opaque\u00e9", "opaque\u2010"]
        for value in invalid:
            with self.subTest(value=repr(value)):
                self.chain.setUp()
                self.url_tokens()
                self.block_token(0, value)
                self.rejected("listed block set or token differs")

    def test_pagination_tokens_use_the_same_bounded_opaque_format(self):
        for value in ("", "A" * 257, "page.token", "page:token", "page token",
                      "page\n", "page\x00", "page\u00e9"):
            with self.subTest(value=repr(value)):
                self.chain.setUp()
                self.url_tokens()
                self.page_token("list-0", "list-1", value)
                self.rejected("invalid or repeated snapshot pagination token")

    def test_url_safe_tokens_do_not_weaken_exact_block_rows(self):
        for field, value in (("BlockIndex", True), ("BlockIndex", 1),
                             ("BlockIndex", 2), ("BlockToken", None), ("BlockToken", 123)):
            with self.subTest(field=field, value=value):
                self.chain.setUp()
                self.url_tokens()
                self.chain.records["list-1"].response["Blocks"][0][field] = value
                self.rejected("listed block set or token differs")
        self.chain.setUp()
        self.url_tokens()
        del self.chain.records["list-1"].response["Blocks"][0]["BlockToken"]
        self.rejected("listed block set or token differs")

    def test_changed_get_token_or_checksum_is_rejected_before_readback(self):
        for side, key, value, reason in (
                ("request", "BlockToken", "different_valid-opaque_", "readback snapshot, index or token differs"),
                ("response", "Checksum", "wrong", "block checksum differs")):
            with self.subTest(field=key):
                self.chain.setUp()
                self.url_tokens()
                getattr(self.chain.records["get-2"], side)[key] = value
                self.rejected(reason)

    def test_url_safe_pagination_still_requires_exact_continuity(self):
        self.url_tokens()
        self.chain.records["list-1"].request["NextToken"] = "different-valid_"
        self.rejected("snapshot pagination continuity differs")
        self.chain.setUp()
        self.url_tokens()
        self.chain.records["list-1"].response["NextToken"] = self.chain.records[
            "list-0"].response["NextToken"]
        self.rejected("invalid or repeated snapshot pagination token")


if __name__ == "__main__":
    unittest.main()
