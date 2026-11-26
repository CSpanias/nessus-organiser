import os
import io
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch
from xml.sax.saxutils import escape

from nessus_organiser.cli import all_reports
from nessus_organiser.common.progress import load_scan
from nessus_organiser.parsing.nessus import load_nessus
from rich.console import Console


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
    def test_interactive_all_clears_progress_before_summaries_and_finishes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            scan = base / "scan.nessus"
            scan.write_text(
                scan_xml().replace(
                    '<ReportItem pluginID="71049" pluginName="SSH" severity="2" port="22" protocol="tcp"/>',
                    "",
                ),
                encoding="utf-8",
            )
            output = io.StringIO()
            console = Console(
                file=output, force_terminal=True, force_interactive=True,
                legacy_windows=False, width=100,
            )
            with redirect_stdout(output), redirect_stderr(output), \
                 patch("nessus_organiser.common.progress.Console", return_value=console), \
                 patch.object(
                     all_reports, "report_path",
                     side_effect=lambda name, timestamp: base / f"{name}.html",
                 ):
                all_reports.run(scan, "internal")

            rendered = output.getvalue()
            for title in (
                "TLS Analysis Summary", "Patch Management Analysis Summary",
                "Closure Review Summary",
            ):
                with self.subTest(title=title):
                    self.assertRegex(
                        rendered, r"\r\x1b\[2K(?:\x1b\[[0-9;]*m)*\s*" + re.escape(title)
                    )
            self.assertNotIn("No findings for Insecure SSH", rendered)
            self.assertRegex(
                rendered, r"\r\x1b\[2K\n[^\r\n]*\r\x1b\[2KReports complete"
            )
            plain = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", rendered)
            self.assertRegex(plain, r"Reports complete[^\r\n]*100% 4/4")

    def test_interactive_scan_progress_reports_real_host_counts(self) -> None:
        output = io.StringIO()
        console = Console(file=output, force_terminal=True, width=100)

        def fake_load(path, on_progress):
            on_progress(0, 2)
            time.sleep(0.15)
            on_progress(1, 2)
            time.sleep(0.15)
            on_progress(2, 2)
            return []

        with patch("nessus_organiser.common.progress.Console", return_value=console), \
             patch("nessus_organiser.common.progress.load_nessus", side_effect=fake_load):
            self.assertEqual(load_scan(Path("scan.nessus")), [])
        self.assertIn("Processing hosts", output.getvalue())
        self.assertIn("1/2", output.getvalue())

    def test_parser_reports_host_progress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scan = Path(directory) / "scan.nessus"
            scan.write_text(
                '<NessusClientData_v2><Report><ReportHost name="one"/>'
                '<ReportHost name="two"/></Report></NessusClientData_v2>',
                encoding="utf-8",
            )
            updates = []
            self.assertEqual(load_nessus(scan, on_progress=lambda done, total: updates.append((done, total))), [])
            self.assertEqual(updates, [(0, 2), (1, 2), (2, 2)])

    def test_all_loads_scan_once_and_shares_findings(self) -> None:
        findings = []
        with patch.object(all_reports, "load_scan", return_value=findings) as load, \
             patch.object(all_reports.tls, "analyse", return_value=None) as tls, \
             patch.object(all_reports.patching, "analyse", return_value=None) as patching, \
             patch.object(all_reports.ssh, "analyse", return_value=None) as ssh, \
             patch.object(all_reports.closure, "analyse", return_value=None) as closure:
            all_reports.run(Path("scan.nessus"), "internal")
        load.assert_called_once_with(Path("scan.nessus"))
        for command in (tls, patching, ssh, closure):
            self.assertIs(command.call_args.args[0], findings)

    def reports(self, base: Path, name: str) -> list[Path]:
        return sorted((base / "nessus-organiser").glob(f"{name}-*.html"))

    def only_report(self, base: Path, name: str) -> Path:
        paths = self.reports(base, name)
        self.assertEqual(len(paths), 1, paths)
        return paths[0]

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
            output = self.only_report(base, "nessus-review")
            self.assertEqual(list((base / "nessus-organiser").glob("*.html")), [output])
            combined = output.read_text(encoding="utf-8")
            for label in ("TLS/SSL", "Patch Management", "SSH", "Closure"):
                self.assertIn(f">{label}</button>", combined)
            ids = re.findall(r'(?<![\w-])id="([^"]+)"', combined)
            self.assertEqual(len(ids), len(set(ids)))
            self.assertIn('role="tablist" aria-label="Reports" hidden', combined)
            for index in range(4):
                self.assertIn(
                    f'role="tabpanel" id="report-{index}-panel" '
                    f'aria-labelledby="report-{index}-tab">', combined
                )
            self.assertNotIn("Search findings", combined)
            self.assertNotIn('type="search"', combined)
            self.assertIn(output.name, result.stdout)
            panels = re.split(r'(?=<section class="report-content" role="tabpanel")', combined)
            self.assertEqual(len(panels), 5)
            tls, patching, ssh, report = panels[1:]
            self.assertIn("Insecure SSH Cryptographic Configuration", ssh)
            tls_remediation = tls.split('<section class="panel"><h2>Remediation</h2>', 1)[1].split("</section>", 1)[0]
            self.assertIn("Strengthen TLS configurations across affected services", tls_remediation)
            self.assertIn("<h3>References</h3>", tls_remediation)
            self.assertIn('href="https://learn.microsoft.com/en-us/dotnet/core/extensions/sslstream-best-practices"', tls_remediation)
            self.assertNotIn('<section class="panel"><h2>References</h2>', tls)
            for expected in ("10114", "35371", "hostname.bind",
                             "Assessment scope: internal.",
                             "www.tenable.com/plugins/nessus/10114",
                             "www.tenable.com/plugins/nessus/35371"):
                self.assertIn(expected, report)
            self.assertNotIn("host-a", report)
            self.assertIn("The following findings are closed in the internal assessment context.", report)
            cards = re.findall(r'<article class="finding">(.*?)</article>', report, re.S)
            self.assertEqual(len(cards), 2)
            for plugin_id in ("10114", "35371"):
                card = next(card for card in cards if f"Nessus {plugin_id}</span>" in card)
                self.assertIn("<summary>Closure Justification</summary>", card)
                self.assertIn(f'href="https://www.tenable.com/plugins/nessus/{plugin_id}"', card)
                self.assertIn("<h4>References</h4>", card)
                self.assertNotIn("<summary>Remediation</summary>", card)
                self.assertIn("finding is therefore closed.", " ".join(card.split()))
                self.assertNotIn("Closure may be appropriate", " ".join(card.split()))
            self.assertNotIn('<section class="panel"><h2>References</h2>', report)
            self.assertNotIn("# Remediation", report)
            self.assertIn("ITHC", patching)
            self.assertIn("csrc.nist.gov/pubs/sp/800/40/r4/final", patching)
            remediation = patching.split('<section class="panel"><h2>Remediation</h2>', 1)[1].split("</section>", 1)[0]
            self.assertIn("Address the identified issues through a risk-based patch", remediation)
            self.assertIn("<h3>References</h3>", remediation)
            self.assertIn('href="https://csrc.nist.gov/pubs/sp/800/40/r4/final"', remediation)
            self.assertNotIn('<section class="panel"><h2>References</h2>', patching)

    def test_external_and_unmatched_scans_do_not_create_or_modify_closure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            scan = base / "scan.nessus"
            scan.write_text(scan_xml(), encoding="utf-8")
            output_dir = base / "nessus-organiser"
            output_dir.mkdir()
            old_report = output_dir / "closure-review-20261123-123456-000000.html"
            old_report.write_text("existing", encoding="utf-8")
            result = self.run_cli(directory, "closure", "-S", "external", "scan.nessus")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Closure Review Summary", result.stdout)
            self.assertEqual(old_report.read_text(encoding="utf-8"), "existing")
            self.assertEqual(self.reports(base, "closure-review"), [old_report])
            scan.write_text(scan_xml(include_icmp=False, include_dns=False), encoding="utf-8")
            result = self.run_cli(directory, "closure", "-S", "internal", "scan.nessus")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(old_report.read_text(encoding="utf-8"), "existing")
            self.assertEqual(self.reports(base, "closure-review"), [old_report])
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "")

    def test_dns_only_is_reported_for_internal_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "scan.nessus").write_text(
                scan_xml(include_icmp=False), encoding="utf-8"
            )
            result = self.run_cli(directory, "closure", "-S", "internal", "scan.nessus")
            self.assertEqual(result.returncode, 0, result.stderr)
            report = self.only_report(base, "closure-review").read_text(encoding="utf-8")
            self.assertIn("35371", report)
            self.assertIn("hostname.bind", report)
            self.assertNotIn("10114", report)
            self.assertIn("Assessment scope: internal.", report)

    def test_external_all_does_not_generate_closure_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "scan.nessus").write_text(scan_xml(), encoding="utf-8")
            result = self.run_cli(directory, "all", "-S", "external", "scan.nessus")
            self.assertEqual(result.returncode, 0, result.stderr)
            report = self.only_report(base, "nessus-review").read_text(encoding="utf-8")
            self.assertIn(">TLS/SSL</button>", report)
            self.assertNotIn(">Closure</button>", report)
            self.assertEqual(self.reports(base, "closure-review"), [])
            self.assertIn("No closure rules are defined for external scope", result.stderr)

    def test_internal_ntp_and_optional_platform_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "scan.nessus").write_text(
                scan_xml(include_icmp=False, include_ntp=True), encoding="utf-8"
            )
            for command in ("closure", "all"):
                with self.subTest(command=command):
                    report_name = "closure-review" if command == "closure" else "nessus-review"
                    previous = set(self.reports(base, report_name))
                    result = self.run_cli(directory, command, "-S", "internal", "scan.nessus")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    created = set(self.reports(base, report_name)) - previous
                    self.assertEqual(len(created), 1)
                    report = created.pop().read_text(encoding="utf-8")
                    self.assertIn('<span class="badge">Nessus 10884</span>', report)
                    self.assertNotIn("SC-2101", report)
                    self.assertIn("limited additional attack value", report)
                    self.assertIn("www.tenable.com/plugins/nessus/10884", report)
                    self.assertIn("The finding is therefore closed.", " ".join(report.split()))
                    self.assertNotIn("Closure may be appropriate", " ".join(report.split()))
                    self.assertNotIn("host-a", report)

                    previous = set(self.reports(base, report_name))
                    result = self.run_cli(
                        directory, command, "-S", "internal", "--csacyber", "scan.nessus"
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    created = set(self.reports(base, report_name)) - previous
                    self.assertEqual(len(created), 1)
                    report = created.pop().read_text(encoding="utf-8")
                    self.assertIn(
                        '<span class="badge">Nessus 10884</span>'
                        '<span class="badge">SureCloud SC-2101</span>', report
                    )
                    self.assertIn('<span class="badge">Nessus 35371</span>', report)
                    self.assertEqual(report.count("SC-2101"), 1)

                    help_result = self.run_cli(directory, command, "--help")
                    self.assertEqual(help_result.returncode, 0)
                    self.assertNotIn("--csacyber", help_result.stdout)

            previous = set(self.reports(base, "closure-review"))
            result = self.run_cli(
                directory, "closure", "-S", "external", "--csacyber", "scan.nessus"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(set(self.reports(base, "closure-review")), previous)

    def test_scope_is_required_and_output_option_is_rejected(self) -> None:
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
                    self.assertIn("unrecognized arguments", result.stderr)
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
            output_dir = base / "nessus-organiser"
            output_dir.mkdir()
            old_report = output_dir / "ssh-review-20261123-123456-000000.html"
            old_report.write_text("existing", encoding="utf-8")
            result = self.run_cli(directory, "all", "-S", "internal", "scan.nessus")
            self.assertEqual(result.returncode, 0, result.stderr)
            report = self.only_report(base, "nessus-review").read_text(encoding="utf-8")
            self.assertIn(">TLS/SSL</button>", report)
            self.assertIn(">Patch Management</button>", report)
            self.assertNotIn(">SSH</button>", report)
            self.assertNotIn(">Closure</button>", report)
            self.assertEqual(old_report.read_text(encoding="utf-8"), "existing")
            self.assertEqual(self.reports(base, "ssh-review"), [old_report])
            self.assertNotIn("SSH Analysis Summary", result.stdout)
            self.assertNotIn("no report was generated", " ".join(result.stderr.split()))
            self.assertNotIn("No findings for", result.stdout)
            self.assertEqual(self.reports(base, "closure-review"), [])

    def test_unmatched_individual_reports_are_not_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "scan.nessus").write_text(
                '<NessusClientData_v2><Report><ReportHost name="host-a">'
                '<ReportItem pluginID="999" pluginName="Unrelated" severity="0" port="0"/>'
                '</ReportHost></Report></NessusClientData_v2>',
                encoding="utf-8",
            )
            for command in ("tls", "ssh", "patching", "all"):
                with self.subTest(command=command):
                    result = self.run_cli(
                        directory, command, "-S", "internal", "scan.nessus"
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse((base / "nessus-organiser").exists())
                    self.assertNotIn("Analysis Summary", result.stdout)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "")

    def test_all_with_only_closure_findings_has_one_tab(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "scan.nessus").write_text(
                '<NessusClientData_v2><Report><ReportHost name="host-a">'
                '<ReportItem pluginID="10884" pluginName="NTP" severity="0" '
                'port="123" protocol="udp"/>'
                '</ReportHost></Report></NessusClientData_v2>',
                encoding="utf-8",
            )
            result = self.run_cli(directory, "all", "-S", "internal", "scan.nessus")
            self.assertEqual(result.returncode, 0, result.stderr)
            report = self.only_report(base, "nessus-review").read_text(encoding="utf-8")
            self.assertEqual(len(re.findall(r'<button type="button" role="tab"', report)), 1)
            self.assertIn(">Closure</button>", report)
            self.assertIn("Closure Review Summary", result.stdout)
            self.assertNotIn("Analysis Summary", result.stdout)

    def test_combined_summary_uses_collision_resolved_filename(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            scan = base / "scan.nessus"
            scan.write_text(scan_xml(), encoding="utf-8")
            output = base / "nessus-review.html"
            output.write_text("existing", encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout), patch.object(all_reports, "report_path", return_value=output):
                all_reports.run(scan, "internal")
            self.assertEqual(output.read_text(encoding="utf-8"), "existing")
            self.assertTrue((base / "nessus-review-1.html").is_file())
            self.assertEqual(stdout.getvalue().count("nessus-review-1.html"), 4)

    def test_runs_create_timestamped_reports_without_overwriting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "scan.nessus").write_text(scan_xml(), encoding="utf-8")
            first = self.run_cli(directory, "all", "-S", "internal", "scan.nessus")
            self.assertEqual(first.returncode, 0, first.stderr)
            output_dir = base / "nessus-organiser"
            initial = {path: path.read_bytes() for path in output_dir.glob("*.html")}
            self.assertEqual(len(initial), 1)
            timestamps = set()
            for path in initial:
                match = re.search(r"-(\d{8}-\d{6})\.html$", path.name)
                if match is None:
                    self.fail(f"Missing timestamp: {path.name}")
                timestamps.add(match.group(1))
            self.assertEqual(len(timestamps), 1)

            second = self.run_cli(directory, "all", "-S", "internal", "scan.nessus")
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(len(list(output_dir.glob("*.html"))), 2)
            for path, contents in initial.items():
                self.assertEqual(path.read_bytes(), contents)

    def test_individual_commands_generate_timestamped_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "scan.nessus").write_text(scan_xml(), encoding="utf-8")
            for command, name, summary in (
                ("tls", "tls-review", "TLS Analysis Summary"),
                ("ssh", "ssh-review", "SSH Analysis Summary"),
                ("patching", "patch-management-review", "Patch Management Analysis Summary"),
                ("closure", "closure-review", "Closure Review Summary"),
            ):
                with self.subTest(command=command):
                    result = self.run_cli(directory, command, "-S", "internal", "scan.nessus")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(summary, result.stdout)
                    report = self.only_report(base, name)
                    self.assertTrue(report.is_file())
                    self.assertIn(report.name, result.stdout)


if __name__ == "__main__":
    unittest.main()
