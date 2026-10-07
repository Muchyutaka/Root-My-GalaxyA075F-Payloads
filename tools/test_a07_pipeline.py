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

    def test_profile_requires_one_verified_rt_mutex_waiter_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profile.json"
            values = {name: 1 for name in extract_a07_offsets.PROFILE_REQUIRED_MACROS}
            values["LEGACY_RT_MUTEX_WAITER"] = 0
            values["COMPACT_RT_MUTEX_WAITER"] = 0
            profile = {
                "model": "SM-A075F",
                "kernelVersion": "6.12.38",
                "macros": values,
                "evidence": {name: "verified from local test fixture" for name in values},
            }
            profile_path.write_text(json.dumps(profile))

            _, _, missing = extract_a07_offsets.profile_values(profile_path)
            self.assertIn(
                "select exactly one of LEGACY_RT_MUTEX_WAITER or COMPACT_RT_MUTEX_WAITER",
                missing,
            )

            profile["macros"]["COMPACT_RT_MUTEX_WAITER"] = 1
            profile_path.write_text(json.dumps(profile))
            _, _, missing = extract_a07_offsets.profile_values(profile_path)
            self.assertEqual(missing, [])

    def test_profile_rejects_non_object_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profile.json"
            profile_path.write_text("[]")
            with self.assertRaisesRegex(ValueError, "must be an object"):
                extract_a07_offsets.profile_values(profile_path)

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
            self.assertEqual(row["managerPackage"], package)
            self.assertEqual(row["kernelsu"]["size"], daemon.stat().st_size)
            self.assertEqual(row["kernelsu"]["sha256"], hashlib.sha256(daemon.read_bytes()).hexdigest())
            self.assertIn("raw.githubusercontent.com/owner/payloads/feature/a07/", row["exploit"]["url"])
            self.assertIn("/artifacts/a07-SM-A075F/cve-2026-43499-app.so", row["exploit"]["url"])

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
