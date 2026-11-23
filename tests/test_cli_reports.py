import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]


def scan_xml(
    include_icmp: bool = True, include_dns: bool = True, include_ntp: bool = False
) -> str:
    items = [
        '<ReportItem pluginID="104743" pluginName="TLS" severity="2" port="443" protocol="tcp"/>',
        '<ReportItem pluginID="71049" pluginName="SSH" severity="2" port="22" protocol="tcp"/>',
        '<ReportItem pluginID="156103" pluginName="Legacy" severity="3" port="0" protocol="tcp"/>',
        '<ReportItem pluginID="1234" pluginName="Patch" severity="3" port="0" protocol="tcp">'
        '<solution>Apply security update</solution><cvss3_base_score>9.0</cvss3_base_score></ReportItem>',
    ]
    if include_icmp:
        items.append(
            '<ReportItem pluginID="10114" pluginName="ICMP timestamp" '
            'severity="2" port="0" protocol="icmp"/>'
        )
    if include_dns:
        items.append(
            '<ReportItem pluginID="35371" pluginName="DNS hostname disclosure" '
            'severity="0" port="53" protocol="udp"/>'
        )
    if include_ntp:
        items.append(
            '<ReportItem pluginID="10884" pluginName="NTP Server Detection" '
            'severity="0" port="123" protocol="udp"/>'
        )
    host = escape("host-a")
    return (
        f'<NessusClientData_v2><Report><ReportHost name="{host}">'
        + "".join(items) + "</ReportHost></Report></NessusClientData_v2>"
    )


class CliReportTests(unittest.TestCase):
    def run_cli(self, directory: str, *args: str) -> subprocess.CompletedProcess:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [sys.executable, "-m", "nessus_organiser.cli.main", *args],
            cwd=directory, env=environment, text=True, capture_output=True,
        )

    def test_internal_all_generates_reports_and_scoped_closure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "scan.nessus").write_text(scan_xml(), encoding="utf-8")
            result = self.run_cli(directory, "all", "-S", "internal", "--ithc", "scan.nessus")
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("tls-review.html", "ssh-review.html", "patch-management-review.html",
                         "closure-review.html"):
                self.assertTrue((base / name).is_file(), name)
            report = (base / "closure-review.html").read_text(encoding="utf-8")
            for expected in ("10114", "35371", "hostname.bind", "host-a",
                             "internal assessments only", "time-based authentication",
                             "www.tenable.com/plugins/nessus/10114",
                             "www.tenable.com/plugins/nessus/35371"):
                self.assertIn(expected, report)
            self.assertIn("not automatic decisions", report)
            patching = (base / "patch-management-review.html").read_text(encoding="utf-8")
            self.assertIn("ITHC", patching)
            self.assertIn("csrc.nist.gov/pubs/sp/800/40/r4/final", patching)

    def test_external_and_unmatched_scans_do_not_create_or_modify_closure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            scan = base / "scan.nessus"
            scan.write_text(scan_xml(), encoding="utf-8")
            old_report = base / "closure-review.html"
            old_report.write_text("existing", encoding="utf-8")
            result = self.run_cli(directory, "closure", "-S", "external", "scan.nessus")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(old_report.read_text(encoding="utf-8"), "existing")
            self.assertIn("not updated", result.stderr)
            old_report.unlink()
            scan.write_text(scan_xml(include_icmp=False, include_dns=False), encoding="utf-8")
            result = self.run_cli(directory, "closure", "-S", "internal", "scan.nessus")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(old_report.exists())
            self.assertIn("No closure-review plugins were found", result.stderr)

    def test_dns_only_is_reported_for_internal_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "scan.nessus").write_text(
                scan_xml(include_icmp=False), encoding="utf-8"
            )
            result = self.run_cli(directory, "closure", "-S", "internal", "scan.nessus")
            self.assertEqual(result.returncode, 0, result.stderr)
            report = (base / "closure-review.html").read_text(encoding="utf-8")
            self.assertIn("35371", report)
            self.assertIn("hostname.bind", report)
            self.assertNotIn("10114", report)
            self.assertIn("internal assessments only", report)

    def test_external_all_does_not_generate_closure_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "scan.nessus").write_text(scan_xml(), encoding="utf-8")
            result = self.run_cli(directory, "all", "-S", "external", "scan.nessus")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((base / "tls-review.html").is_file())
            self.assertFalse((base / "closure-review.html").exists())
            self.assertIn("No closure rules are defined for external scope", result.stderr)

    def test_internal_ntp_and_optional_platform_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "scan.nessus").write_text(
                scan_xml(include_icmp=False, include_ntp=True), encoding="utf-8"
            )
            for command in ("closure", "all"):
                with self.subTest(command=command):
                    result = self.run_cli(directory, command, "-S", "internal", "scan.nessus")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    report = (base / "closure-review.html").read_text(encoding="utf-8")
                    self.assertIn('<span class="badge">Nessus 10884</span>', report)
                    self.assertNotIn("SC-2101", report)
                    self.assertIn("limited additional attack value", report)
                    self.assertIn("amplification functionality", report)
                    self.assertIn("www.tenable.com/plugins/nessus/10884", report)

                    result = self.run_cli(
                        directory, command, "-S", "internal", "--csacyber", "scan.nessus"
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    report = (base / "closure-review.html").read_text(encoding="utf-8")
                    self.assertIn('<span class="badge">Nessus 10884 | SC-2101</span>', report)
                    self.assertIn('<span class="badge">Nessus 35371</span>', report)
                    self.assertEqual(report.count("SC-2101"), 1)

                    help_result = self.run_cli(directory, command, "--help")
                    self.assertEqual(help_result.returncode, 0)
                    self.assertNotIn("--csacyber", help_result.stdout)

            (base / "closure-review.html").unlink()
            result = self.run_cli(
                directory, "closure", "-S", "external", "--csacyber", "scan.nessus"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((base / "closure-review.html").exists())

    def test_scope_is_required_and_markdown_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "scan.nessus").write_text(scan_xml(), encoding="utf-8")
            for command in ("all", "tls", "ssh", "patching", "closure"):
                with self.subTest(command=command):
                    result = self.run_cli(directory, command, "scan.nessus")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("required", result.stderr)
                    self.assertIn("--scope", result.stderr)
            for command in ("tls", "ssh", "patching", "closure"):
                with self.subTest(command=command):
                    result = self.run_cli(
                        directory, command, "-S", "internal", "-o", "custom.md", "scan.nessus"
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("output must end in .html", result.stderr)
            self.assertFalse((base / "custom.md").exists())
            result = self.run_cli(
                directory, "all", "-S", "internal", "--format", "markdown", "scan.nessus"
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((base / "tls-review.md").exists())
            missing = self.run_cli(directory, "tls", "-S", "internal", "missing.nessus")
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("Nessus input file not found", missing.stderr)
            self.assertNotIn("Traceback", missing.stderr)

    def test_all_skips_ssh_when_only_tls_and_patching_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "scan.nessus").write_text(
                '<NessusClientData_v2><Report><ReportHost name="host-a">'
                '<ReportItem pluginID="104743" pluginName="TLS" severity="2" port="443" protocol="tcp"/>'
                '<ReportItem pluginID="1234" pluginName="Patch" severity="3" port="0" protocol="tcp">'
                '<solution>Apply security update</solution></ReportItem>'
                '</ReportHost></Report></NessusClientData_v2>',
                encoding="utf-8",
            )
            old_report = base / "ssh-review.html"
            old_report.write_text("existing", encoding="utf-8")
            result = self.run_cli(directory, "all", "-S", "internal", "scan.nessus")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((base / "tls-review.html").is_file())
            self.assertTrue((base / "patch-management-review.html").is_file())
            self.assertEqual(old_report.read_text(encoding="utf-8"), "existing")
            self.assertIn("Not generated", result.stdout)
            self.assertIn("Existing report 'ssh-review.html' was not updated", result.stderr)
            self.assertFalse((base / "closure-review.html").exists())

    def test_unmatched_individual_reports_are_not_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "scan.nessus").write_text(
                '<NessusClientData_v2><Report><ReportHost name="host-a">'
                '<ReportItem pluginID="999" pluginName="Unrelated" severity="0" port="0"/>'
                '</ReportHost></Report></NessusClientData_v2>',
                encoding="utf-8",
            )
            for command in ("tls", "ssh", "patching"):
                with self.subTest(command=command):
                    output = base / f"{command}.html"
                    result = self.run_cli(
                        directory, command, "-S", "internal", "-o", output.name, "scan.nessus"
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(output.exists())
                    self.assertIn("Not generated", result.stdout)
                    self.assertIn("no report was generated", " ".join(result.stderr.split()))


if __name__ == "__main__":
    unittest.main()
