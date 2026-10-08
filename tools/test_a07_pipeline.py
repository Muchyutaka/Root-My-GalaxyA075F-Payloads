from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "tools" / "generate_a07_targets.py"
sys.path.insert(0, str(ROOT / "tools"))
import extract_a07_offsets  # noqa: E402


class A07ExtractionHelperTests(unittest.TestCase):
    def test_task_struct_mm_is_found_only_inside_task_struct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            header = Path(tmp) / "sched.h"
            header.write_text(
                "struct mm_struct;\n"
                "struct task_struct {\n"
                "  int pid;\n"
                "  struct mm_struct *mm; /* source declaration */\n"
                "};\n"
                "struct other { struct mm_struct *mm; };\n"
            )
            ok, line, declaration = extract_a07_offsets.task_struct_source_mm(header)
            self.assertTrue(ok)
            self.assertEqual(line, 4)
            self.assertEqual(declaration, "struct mm_struct *mm; /* source declaration */")

    def test_task_struct_mm_missing_is_not_satisfied_by_another_struct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            header = Path(tmp) / "sched.h"
            header.write_text(
                "struct task_struct { int pid; };\n"
                "struct other { struct mm_struct *mm; };\n"
            )
            ok, line, declaration = extract_a07_offsets.task_struct_source_mm(header)
            self.assertFalse(ok)
            self.assertIsNone(line)
            self.assertIsNone(declaration)

    def test_c_literals_reject_multiline_or_directive_values(self) -> None:
        self.assertEqual(extract_a07_offsets.c_literal("0x10000ULL, 0x20000ULL"), "0x10000ULL, 0x20000ULL")
        with self.assertRaises(ValueError):
            extract_a07_offsets.c_literal("0x10000ULL\n#error bad")

    def test_slide_chain_addresses_are_measured_not_profiled(self) -> None:
        for macro in extract_a07_offsets.SLIDE_CHAIN_MACROS:
            self.assertNotIn(macro, extract_a07_offsets.PROFILE_REQUIRED_MACROS)
        self.assertEqual(4, len(extract_a07_offsets.SLIDE_CHAIN_MACROS))

    def test_profile_no_longer_carries_layout_flags(self) -> None:
        # The waiter layout is measured from A07's BTF, so a profile must not supply it by hand.
        for name in ("LEGACY_RT_MUTEX_WAITER", "COMPACT_RT_MUTEX_WAITER", "NESTED_RT_MUTEX_WAITER"):
            self.assertNotIn(name, extract_a07_offsets.PROFILE_REQUIRED_MACROS)
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profile.json"
            values = {name: 1 for name in extract_a07_offsets.PROFILE_REQUIRED_MACROS}
            profile = {
                "model": "SM-A075F",
                "kernelVersion": "6.12.38",
                "macros": values,
                "evidence": {name: "verified from local test fixture" for name in values},
            }
            profile_path.write_text(json.dumps(profile))
            _, _, missing = extract_a07_offsets.profile_values(profile_path)
            self.assertEqual(missing, [])

    def test_waiter_layout_flags_select_exactly_one_layout(self) -> None:
        a07 = {"lock", "pi_tree", "task", "tree", "wake_state", "ww_ctx"}
        flags, evidence = extract_a07_offsets.waiter_layout_flags(a07)
        self.assertEqual({"LEGACY_RT_MUTEX_WAITER": "0", "COMPACT_RT_MUTEX_WAITER": "0",
                          "NESTED_RT_MUTEX_WAITER": "1"}, flags)
        self.assertIn("tree", evidence)

        legacy = {"tree_entry", "pi_tree_entry", "pi_tree_prio", "pi_tree_deadline", "task", "lock"}
        self.assertEqual("1", extract_a07_offsets.waiter_layout_flags(legacy)[0]["LEGACY_RT_MUTEX_WAITER"])
        compact = {"tree_entry", "pi_tree_entry", "task", "lock", "prio", "deadline"}
        self.assertEqual("1", extract_a07_offsets.waiter_layout_flags(compact)[0]["COMPACT_RT_MUTEX_WAITER"])

        ambiguous, reason = extract_a07_offsets.waiter_layout_flags(set())
        self.assertEqual({}, ambiguous)
        self.assertIn("undetermined", reason)
        # A struct that matches two layouts at once must not be silently resolved either.
        both, reason = extract_a07_offsets.waiter_layout_flags(
            {"tree", "pi_tree", "pi_tree_entry", "pi_tree_prio", "pi_tree_deadline"}
        )
        self.assertEqual({}, both)
        self.assertIn("undetermined", reason)

    def test_workqueue_max_active_relocation_is_derived(self) -> None:
        flags, evidence = extract_a07_offsets.workqueue_max_active_flags(
            {"wq", "pool", "refcnt", "nr_active"}, {"max_active": 0xA4, "dfl_pwq": 0x20}, 0x08
        )
        self.assertEqual({"PWQ_MAX_ACTIVE_VIA_WQ": "1", "WQ_MAX_ACTIVE_OFF": "0xa4ULL"}, flags)
        self.assertIn("pool_workqueue.wq", evidence)

        kept, _ = extract_a07_offsets.workqueue_max_active_flags(
            {"wq", "max_active"}, {"max_active": 0xA4}, 0x08
        )
        self.assertEqual({"PWQ_MAX_ACTIVE_VIA_WQ": "0"}, kept)

        unresolved, reason = extract_a07_offsets.workqueue_max_active_flags({"pool"}, {}, None)
        self.assertEqual({}, unresolved)
        self.assertIn("undetermined", reason)

    def test_layout_flags_reach_the_generated_header_and_cannot_be_overridden(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "target.h"
            extract_a07_offsets.emit_header(
                out, "6.12.38-test", 0xFFFFFFC008000000, {},
                {"workqueue_struct": {"max_active": 0xA4}, "pool_workqueue": {"wq": 0x08}}, {},
                {"macros": {}, "evidence": {}},
                measured_macros={"NESTED_RT_MUTEX_WAITER": "1", "PWQ_MAX_ACTIVE_VIA_WQ": "1",
                                 "WQ_MAX_ACTIVE_OFF": "0xa4ULL"},
            )
            text = out.read_text()
            self.assertIn("#define NESTED_RT_MUTEX_WAITER 1", text)
            self.assertIn("#define PWQ_MAX_ACTIVE_VIA_WQ 1", text)
            self.assertIn("#define WQ_MAX_ACTIVE_OFF 0xa4ULL", text)
            with self.assertRaisesRegex(ValueError, "override extracted macro"):
                extract_a07_offsets.emit_header(
                    out, "6.12.38-test", 0xFFFFFFC008000000, {}, {}, {},
                    {"macros": {"NESTED_RT_MUTEX_WAITER": 0}, "evidence": {}},
                    measured_macros={"NESTED_RT_MUTEX_WAITER": "1"},
                )

    def test_profile_rejects_non_object_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profile.json"
            profile_path.write_text("[]")
            with self.assertRaisesRegex(ValueError, "must be an object"):
                extract_a07_offsets.profile_values(profile_path)

    def test_failed_extraction_removes_stale_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "output"
            output.mkdir()
            (output / "target.h").write_text("stale header")
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/extract_a07_offsets.py"),
                 "--release-assets", str(root / "empty"), "--output-dir", str(output),
                 "--profile", str(ROOT / "src/targets/a07-SM-A075F/target-values.template.json")],
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((output / "target.h").exists())
            self.assertFalse(json.loads((output / "status.json").read_text())["ready"])

    def test_pahole_member_names(self) -> None:
        cases = {
            "        struct module  *               owner;                /*     0x0     0x8 */": "owner",
            "        loff_t                       (*llseek)(struct file  *, loff_t, int); /*     0x8     0x8 */": "llseek",
            "        ssize_t                      (*read)(struct file  *, char  *, size_t, loff_t *); /*    0x10     0x8 */": "read",
            "        u64                            mask:1;               /*    0x28     0x8 */": "mask",
            "        char                           name[16];             /*    0x30    0x10 */": "name",
            "        struct x *                     arr[4];               /*    0x40    0x20 */": "arr",
            "        int                        prio;                 /*    0x40     0x4 */": "prio",
            "        struct rb_node             tree_entry;           /*     0x0    0x18 */": "tree_entry",
        }
        for line, expected in cases.items():
            declaration = line.split("/*", 1)[0]
            self.assertEqual(expected, extract_a07_offsets.member_name(declaration), line)

    def test_pahole_member_embedded_types(self) -> None:
        cases = {
            "        struct rt_waiter_node        tree;               ": ("tree", "rt_waiter_node", False),
            "        struct module  *               owner;              ": ("owner", "module", True),
            "        struct rb_node             node;                 ": ("node", "rb_node", False),
            "        int                        prio;                 ": ("prio", None, False),
            "        loff_t                       (*llseek)(struct file  *, loff_t, int); ": ("llseek", None, False),
        }
        for declaration, expected in cases.items():
            self.assertEqual(expected, extract_a07_offsets.member_declaration(declaration), declaration)

    def test_resolve_btf_path_walks_nested_members(self) -> None:
        fields = {
            "rt_mutex_waiter": {"tree": 0x0, "pi_tree": 0x18, "task": 0x30},
            "rt_waiter_node": {"node": 0x0, "prio": 0x18, "deadline": 0x20},
        }
        types = {"rt_mutex_waiter": {"tree": ("rt_waiter_node", False), "pi_tree": ("rt_waiter_node", False),
                                     "task": ("task_struct", True)}}
        sizes = {"rt_mutex_waiter": 0x40, "rt_waiter_node": 0x28}
        walk = extract_a07_offsets.resolve_btf_path
        offset, evidence, container = walk(fields, types, sizes, lambda name: None, "rt_mutex_waiter", "pi_tree.prio")
        self.assertEqual(0x30, offset)
        self.assertIn("pi_tree@0x18", evidence)
        self.assertEqual("rt_waiter_node", container)
        offset, reason, container = walk(fields, types, sizes, lambda name: None, "rt_mutex_waiter", "task.prio")
        self.assertIsNone(offset)
        self.assertIn("not an embedded", reason)
        self.assertEqual("rt_mutex_waiter", container)
        offset, reason, container = walk(fields, types, sizes, lambda name: None, "rt_mutex_waiter", "tree.absent")
        self.assertIsNone(offset)
        self.assertIn("has no member `absent`", reason)
        self.assertEqual("rt_waiter_node", container)

    def test_resolve_btf_path_refuses_out_of_range_offset(self) -> None:
        fields = {"slab": {"__page": 0x0, "slab_cache": 0x80}}
        offset, reason, container = extract_a07_offsets.resolve_btf_path(
            fields, {}, {"slab": 0x40}, lambda name: None, "slab", "slab_cache"
        )
        self.assertIsNone(offset)
        self.assertIn("outside sizeof(struct slab)", reason)
        self.assertEqual("slab", container)

    def test_slab_derivation_requires_page_at_zero(self) -> None:
        self.assertEqual(("slab", "slab_cache", ("__page", 0), None),
                         extract_a07_offsets.DERIVED_BTF_PATHS["STRUCT_SLAB_CACHE_OFF"])

    def test_pi_tree_entry_requires_an_embedded_rb_node(self) -> None:
        self.assertEqual(("rt_mutex_waiter", "pi_tree.entry", None, "rb_node"),
                         extract_a07_offsets.DERIVED_BTF_PATHS["FAKE_WAITER_PI_TREE_ENTRY_OFF"])

    def test_moved_macros_are_reported_not_substituted(self) -> None:
        old_type, old_member, new_type, note = extract_a07_offsets.MOVED_BTF_MACROS["PWQ_MAX_ACTIVE_OFF"]
        self.assertEqual(("pool_workqueue", "max_active", "workqueue_struct"), (old_type, old_member, new_type))
        self.assertIn("source port", note)

    def test_pahole_non_member_lines(self) -> None:
        for declaration in ("        };", "        union {", "        struct {", "        int", "        unsigned long"):
            self.assertIsNone(extract_a07_offsets.member_name(declaration), declaration)

    def test_samsung_source_accepts_unique_root_kernel_archive(self) -> None:
        if sys.version_info < (3, 12):
            self.skipTest("the safe tarfile data filter is available in CI's Python 3.12")
        import io
        import tarfile
        import zipfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            contents = b"struct task_struct { struct mm_struct *mm; };\n"
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w:gz") as archive:
                info = tarfile.TarInfo("include/linux/sched.h")
                info.size = len(contents)
                archive.addfile(info, io.BytesIO(contents))
            source_zip = root / "source.zip"
            with zipfile.ZipFile(source_zip, "w") as archive:
                archive.writestr("Kernel.tar.gz", raw.getvalue())
            source_root, member = extract_a07_offsets.extract_kernel_source(source_zip, root / "out")
            self.assertEqual(member, "Kernel.tar.gz")
            self.assertTrue((source_root / "include/linux/sched.h").is_file())

    def test_readelf_excludes_undefined_symbols(self) -> None:
        from unittest.mock import patch
        from subprocess import CompletedProcess
        listing = (
            "   1: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND init_task\n"
            "   2: ffffffc080001000   128 OBJECT  GLOBAL DEFAULT   15 root_task_group\n"
        )
        with patch.object(extract_a07_offsets, "run", return_value=CompletedProcess([], 0, listing, "")):
            self.assertEqual(extract_a07_offsets.parse_readelf_symbols(Path("vmlinux")),
                             {"root_task_group": 0xffffffc080001000})

    def test_header_emission_uses_elf_btf_and_explicit_profile_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            header = Path(tmp) / "target.h"
            extract_a07_offsets.emit_header(
                header,
                "6.12.38-test-release",
                0xFFFFFFC080000000,
                {"init_task": 0xFFFFFFC0A0000100},
                {"task_struct": {"mm": 0x98, "usage": 0x40}},
                {"mm_struct": 0x400, "page": 0x40},
                {"macros": {"SKB_DATA_DELTA": -3712, "SLIDE_PSELECT_WORD_SHIFT": 1}},
            )
            text = header.read_text()
            self.assertIn("#define TARGET_A07_SM_A075F 1", text)
            self.assertIn("#define INIT_TASK_OFF 0x20000100ULL", text)
            self.assertIn("#define TASK_STRUCT_MM_OFF 0x98ULL", text)
            self.assertIn("#define MM_STRUCT_SZ 0x400ULL", text)
            self.assertIn("#define SKB_DATA_DELTA -3712LL", text)
            self.assertIn("#define SLIDE_PSELECT_WORD_SHIFT 1", text)
            self.assertIn("#define LOCK_OFF 0x2210", text)
            self.assertIn('#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"', text)
            self.assertIn("#define PIPE_BUF_FLAG_CAN_MERGE 0x10", text)
            self.assertNotIn("APP_S928_STABLE_RACE", text)


class A07FeedGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "artifacts/a07-SM-A075F").mkdir(parents=True)
        (self.root / "kernelsu").mkdir()
        self.app = self.root / "artifacts/a07-SM-A075F/cve-2026-43499-app.so"
        self.app.write_bytes(b"test-app-payload")
        for filename in (
            "ksud-a07-SM-A075F-kdp",
            "ksud-next-a07-SM-A075F-kdp",
            "ksud-rsksu-a07-SM-A075F-kdp",
            "android16-6.12_kernelsu-a07-SM-A075F-kdp.ko",
            "android16-6.12_kernelsu-next-a07-SM-A075F-kdp.ko",
            "android16-6.12_kernelsu-rsksu-a07-SM-A075F-kdp.ko",
        ):
            (self.root / "kernelsu" / filename).write_bytes(filename.encode())
        self.feed = self.root / "targets-v3.json"
        self.feed.write_text(json.dumps({"schemaVersion": 3, "payloads": []}))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def generate(self) -> None:
        subprocess.run(
            [
                sys.executable,
                str(GENERATOR),
                "--feed",
                str(self.feed),
                "--repo",
                "owner/payloads",
                "--ref",
                "feature/a07",
                "--kernel-release",
                "6.12.38-android16-5-abA075FXXS5CZF2-4k",
                "--app",
                str(self.app),
                "--kernelsu-dir",
                str(self.root / "kernelsu"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_writes_exact_flavors_versions_packages_and_hashes(self) -> None:
        self.generate()
        payloads = json.loads(self.feed.read_text())["payloads"]
        self.assertEqual(len(payloads), 3)
        expected = {
            "kernelsu": ("3.3.0", "me.weishu.kernelsu", "ksud-a07-SM-A075F-kdp"),
            "kernelsu-next": ("3.4.0", "com.rifsxd.ksunext", "ksud-next-a07-SM-A075F-kdp"),
            "resukisu": ("4.2.0-rc3", "com.resukisu.resukisu", "ksud-rsksu-a07-SM-A075F-kdp"),
        }
        for row in payloads:
            flavor = row["flavor"]
            version, package, daemon_name = expected[flavor]
            daemon = self.root / "kernelsu" / daemon_name
            self.assertEqual(row["models"], ["SM-A075F"])
            self.assertEqual(row["kernelVersions"], ["6.12.38", "6.12.38-android16-5-abA075FXXS5CZF2-4k"])
            self.assertEqual(row["kernelsu"]["version"], version)
            self.assertNotIn("managerPackage", row)
            self.assertNotIn("kernelModule", row)
            self.assertEqual(row["kernelsu"]["size"], daemon.stat().st_size)
            self.assertEqual(row["kernelsu"]["sha256"], hashlib.sha256(daemon.read_bytes()).hexdigest())
            self.assertIn("raw.githubusercontent.com/owner/payloads/feature/a07/", row["exploit"]["url"])
            self.assertIn("/artifacts/a07-SM-A075F/cve-2026-43499-app.so", row["exploit"]["url"])

    def test_missing_pair_prevents_partial_feed(self) -> None:
        (self.root / "kernelsu/android16-6.12_kernelsu-rsksu-a07-SM-A075F-kdp.ko").unlink()
        before = self.feed.read_bytes()
        with self.assertRaises(subprocess.CalledProcessError):
            self.generate()
        self.assertEqual(self.feed.read_bytes(), before)

    def test_generation_is_idempotent(self) -> None:
        self.generate()
        self.generate()
        self.assertEqual(len(json.loads(self.feed.read_text())["payloads"]), 3)

    def test_refuses_wrong_kernel_release(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(GENERATOR),
                "--feed",
                str(self.feed),
                "--repo",
                "owner/payloads",
                "--ref",
                "main",
                "--kernel-release",
                "6.12.37-test",
                "--app",
                str(self.app),
                "--kernelsu-dir",
                str(self.root / "kernelsu"),
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a 6.12.38 release", result.stderr)


if __name__ == "__main__":
    unittest.main()
