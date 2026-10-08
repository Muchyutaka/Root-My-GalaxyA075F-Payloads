"""Offline tests for the annotation summarizer (the only CI channel the sandbox can read)."""

import json
import tempfile
import unittest
from pathlib import Path

from tools.summarize_a07_status import classify, notices

STATUS = {
    "ready": False,
    "kernelRelease": "6.12.38-android16-5-abA075FXXS5CZF2-4k",
    "warnings": ["supplied kernel.elf is incomplete"],
    "missing": [
        "symbol `selinux_enforcing` required for SELINUX_ENFORCING_OFF; closest ELF matches: selinux_enforcing_boot",
        "P0_PAGE_OFFSET (missing profile value)",
        "P0_PAGE_OFFSET (missing evidence string)",
        "converted kernel.raw ELF remains incomplete: missing target-header symbols",
    ],
}
LAYOUTS = {"task_struct_mm": {"btfOffset": 1672, "verified": True}}
SYMBOLS = {"kernelRelease": STATUS["kernelRelease"], "offsetMacros": {"INIT_TASK_OFF": "0x1234"}}


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "status.json").write_text(json.dumps(STATUS))
        (root / "btf-layouts.json").write_text(json.dumps(LAYOUTS))
        (root / "symbol-offsets.json").write_text(json.dumps(SYMBOLS))
        self.root = root

    def tearDown(self):
        self.tmp.cleanup()

    def test_classification(self):
        groups = classify(STATUS["missing"])
        self.assertEqual(len(groups["symbols"]), 1)
        self.assertEqual(len(groups["profileValues"]), 1)
        self.assertEqual(len(groups["profileEvidence"]), 1)
        self.assertEqual(len(groups["structural"]), 1)

    def test_reports_verified_mm_and_offsets(self):
        text = "\n".join(notices(self.root))
        self.assertIn("task_struct.mm verified=True (offset 1672)", text)
        self.assertIn("INIT_TASK_OFF=0x1234", text)
        self.assertIn("header ready=False", text)
        self.assertIn("selinux_enforcing", text)

    def test_survives_absent_results(self):
        empty = self.root / "empty"
        empty.mkdir()
        text = "\n".join(notices(empty))
        self.assertIn("NOT PARSED", text)
        self.assertIn("header ready=False", text)


if __name__ == "__main__":
    unittest.main()
