import tempfile
import unittest
from pathlib import Path

from nessus_organiser.content.loader import load_patch_management_content
from nessus_organiser.findings.factory import build_findings
from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.reporting import generate_report


def plugin(plugin_id: str, name: str) -> PluginFinding:
    return PluginFinding(
        plugin_id=plugin_id, plugin_name=name, host="host.test", port=0,
        protocol="tcp", service="", severity="High", plugin_output="",
    )


class HtmlReportTests(unittest.TestCase):
    def test_patch_report_preserves_remediation_statistics_and_references(self) -> None:
        content = load_patch_management_content()
        findings = build_findings(
            {
                "unsupported_software": [plugin("1", "Legacy")],
                "missing_security_patches": [plugin("2", "Patch")],
            },
            content,
        )
        for finding in findings:
            finding.severity = "High"
        statistics = {
            "summary": {
                "legacy_vulnerabilities": 1, "patch_vulnerabilities": 1,
                "total_vulnerabilities": 2,
            },
            "high_risk": {"legacy_vulnerabilities": 1, "patch_vulnerabilities": 1},
            "top_legacy_findings": [("<script>alert(1)</script> | test", 7.0, 1, 100)],
            "top_patch_findings": [("Update", 9.0, 1, 100)],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            generate_report(
                findings, path, content["title"], content["introduction"],
                statistics=statistics, ithc=True,
            )
            report = path.read_text(encoding="utf-8")

        self.assertIn("Upgrade, replace, or migrate affected software", report)
        self.assertIn("Apply the vendor-recommended security updates", report)
        self.assertIn("Counts are deduplicated by host and Nessus plugin ID.", report)
        self.assertIn("CVSSv3 base score of 7.0 or greater", report)
        self.assertIn("https://csrc.nist.gov/pubs/sp/800/40/r4/final", report)
        self.assertIn("<table>", report)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt; | test", report)
        self.assertNotIn("<script>alert(1)</script>", report)
        self.assertIn("Copy Markdown", report)
        self.assertIn('id="search"', report)

    def test_non_html_output_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.md"
            with self.assertRaisesRegex(ValueError, "html"):
                generate_report([], path, "Example", introduction="Introduction.")
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
