"""Offline regression tests for fail-closed release input verification."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from tools.verify_a07_release import ASSETS, TAG, release_assets, verify


class ReleaseVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.metadata = {"id": 42, "tag_name": TAG, "draft": False, "assets": []}
        for index, name in enumerate(ASSETS, 1):
            data = name.encode()
            (self.directory / name).write_bytes(data)
            self.metadata["assets"].append({
                "name": name, "id": index, "size": len(data), "state": "uploaded",
                "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            })

    def tearDown(self):
        self.tmp.cleanup()

    def test_verifies_every_input(self):
        receipt = verify(self.metadata, self.metadata, self.directory)
        self.assertEqual(set(receipt["assets"]), set(ASSETS))

    def test_rejects_missing_asset(self):
        (self.directory / "boot.img").unlink()
        with self.assertRaisesRegex(ValueError, "missing, symlinked"):
            verify(self.metadata, self.metadata, self.directory)

    def test_rejects_changed_bytes(self):
        path = self.directory / "dtbo.img"
        path.write_bytes(b"X" * path.stat().st_size)
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            verify(self.metadata, self.metadata, self.directory)

    def test_rejects_missing_digest_before_download(self):
        self.metadata["assets"][0]["digest"] = None
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            release_assets(self.metadata)

    def test_rejects_release_swap(self):
        other = {**self.metadata, "assets": [dict(asset) for asset in self.metadata["assets"]]}
        other["assets"][0]["id"] += 1
        with self.assertRaisesRegex(ValueError, "changed during download"):
            verify(self.metadata, other, self.directory)

    def test_rejects_extra_asset(self):
        self.metadata["assets"].append({"name": "unexpected.img"})
        with self.assertRaisesRegex(ValueError, "unexpected"):
            release_assets(self.metadata)


if __name__ == "__main__":
    unittest.main()
