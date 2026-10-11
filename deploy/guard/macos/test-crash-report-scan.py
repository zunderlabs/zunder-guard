#!/usr/bin/env python3
"""Deterministic temp-file tests; never opens a real DiagnosticReports folder."""
import importlib.util
import json
from pathlib import Path
import tempfile
import os
import subprocess
import sys
import unittest

spec = importlib.util.spec_from_file_location("crash_scan", Path(__file__).with_name("crash-report-scan.py"))
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class CrashReportScan(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="guard-crash-scan-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exe = "/fixture/ci-example/a/broker"

    def report(self, name, payload=b"", path=None):
        report = self.root / name
        report.write_bytes((json.dumps({"procPath": path or self.exe}) + "\n").encode() + payload)
        return report

    def inspect(self, baseline=None):
        return scan.inspect([self.root], baseline or {}, {self.exe})

    def test_cli_refuses_outside_hosted_ci_before_touching_reports(self):
        env = dict(os.environ, GITHUB_ACTIONS="false")
        result = subprocess.run([sys.executable, "-B", str(Path(scan.__file__)), "baseline",
                                 "--fixture-base", str(self.root)], env=env,
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / "crash-baseline.json").exists())
        self.assertNotIn(str(self.root), result.stdout + result.stderr)
        self.assertNotIn(scan.SCALAR, result.stdout + result.stderr)

    def test_no_report_is_explicitly_not_proof(self):
        self.assertEqual(scan.assessment(self.inspect()), "no-fixture-reports-observed")

    def test_clean_fixture_report(self):
        self.report("clean.ips", b"stacktrace without credential")
        counts = self.inspect()
        self.assertEqual(counts["fixture_reports"], 1)
        self.assertEqual(scan.assessment(counts), "observed-fixture-reports-clear")

    def test_ascii_raw_hex_spaced_hex_and_utf16_hits(self):
        for payload in (scan.SCALAR.encode(), bytes.fromhex(scan.SCALAR), scan.SCALAR.encode().hex().encode(),
                        " ".join(scan.SCALAR[i:i+2] for i in range(0, 64, 2)).encode(),
                        scan.SCALAR.encode("utf-16-le"), scan.SCALAR.encode("utf-16-be"),
                        scan.MARKERS[0].encode()):
            with self.subTest(encoding=len(payload)):
                self.report("hit.ips", payload)
                self.assertEqual(scan.assessment(self.inspect()), "synthetic-credential-found")

    def test_baseline_reports_excluded(self):
        self.report("old.ips", scan.SCALAR.encode())
        baseline = scan.snapshot([self.root])
        self.assertEqual(self.inspect(baseline)["new_reports"], 0)

    def test_unrelated_process_and_stack_path_mention_excluded(self):
        self.report("other.ips", (self.exe + scan.SCALAR).encode(), path="/usr/bin/unrelated")
        counts = self.inspect()
        self.assertEqual(counts["fixture_reports"], 0)
        self.assertEqual(counts["matching_reports"], 0)
        self.assertEqual(counts["unscoped_reports"], 1)

    def test_exact_process_path_not_prefix(self):
        self.report("other.ips", scan.SCALAR.encode(), path=self.exe + "-unrelated")
        self.assertEqual(self.inspect()["fixture_reports"], 0)

    def test_legacy_report_path(self):
        (self.root / "legacy.crash").write_bytes(("Process: broker [123]\nPath: " + self.exe + "\n").encode() + scan.SCALAR.encode())
        self.assertEqual(scan.assessment(self.inspect()), "synthetic-credential-found")

    def test_symlink_file_and_directory_not_followed(self):
        with tempfile.TemporaryDirectory(prefix="guard-crash-outside-test-") as other:
            outside = Path(other)
            (outside / "report.ips").write_bytes(scan.SCALAR.encode())
            (self.root / "linked.ips").symlink_to(outside / "report.ips")
            (self.root / "linked-dir").symlink_to(outside, target_is_directory=True)
            self.assertEqual(self.inspect()["new_reports"], 0)

    def test_oversized_fixture_report_fails_closed(self):
        report = self.report("large.ips")
        with report.open("ab") as output:
            output.truncate(scan.MAX_REPORT + 1)
        self.assertEqual(scan.assessment(self.inspect()), "incomplete-scan")


if __name__ == "__main__":
    unittest.main()
