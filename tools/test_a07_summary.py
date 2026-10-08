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
LAYOUTS = {
    "task_struct_mm": {"btfOffset": 1672, "verified": True},
    "rtMutexWaiterLayoutCandidate": "COMPACT_RT_MUTEX_WAITER=1 (BTF carries tree_entry/prio/deadline)",
    "incompleteStructDiagnostics": {"file_operations": {"parsedMembers": ["owner", "llseek", "read"]}},
    "derivedMembers": {
        "STRUCT_SLAB_CACHE_OFF": {"status": "derived", "offset": 40, "root": "slab", "path": "slab_cache"},
        "FAKE_WAITER_TREE_PRIO_OFF": {"status": "unresolved", "root": "rt_mutex_waiter", "path": "tree.prio",
                                     "evidence": "struct rt_waiter_node has no member `prio`",
                                     "types": {"rt_waiter_node": ["node", "deadline"]}},
    },
}
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

    def test_reports_measured_layout_evidence(self):
        text = "\n".join(notices(self.root))
        self.assertIn("rt_mutex_waiter layout measured from A07 BTF: COMPACT_RT_MUTEX_WAITER=1", text)
        self.assertIn("struct file_operations: pahole parsed 3 members: owner, llseek, read", text)

    def test_reports_nested_derivation_status(self):
        text = "\n".join(notices(self.root))
        self.assertIn("STRUCT_SLAB_CACHE_OFF=derived@0x28 (slab.slab_cache)", text)
        self.assertIn("FAKE_WAITER_TREE_PRIO_OFF=unresolved (rt_mutex_waiter.tree.prio)", text)

    def test_reports_unresolved_derivation_detail(self):
        text = "\n".join(notices(self.root))
        self.assertIn("Unresolved derivation FAKE_WAITER_TREE_PRIO_OFF", text)
        self.assertIn("struct rt_waiter_node members: deadline, node", text)

    def test_survives_absent_results(self):
        empty = self.root / "empty"
        empty.mkdir()
        text = "\n".join(notices(empty))
        self.assertIn("NOT PARSED", text)
        self.assertIn("header ready=False", text)


if __name__ == "__main__":
    unittest.main()
