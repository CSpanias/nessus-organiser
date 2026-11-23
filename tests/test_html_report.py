import re
import tempfile
import unittest
from html import unescape
from pathlib import Path

from nessus_organiser.analysis.tls import analyse_tls_finding
from nessus_organiser.content.loader import load_patch_management_content, load_tls_content
from nessus_organiser.findings.factory import build_findings
from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.organising.tls import build_evidence, organise_tls
from nessus_organiser.reporting import generate_report
from nessus_organiser.reporting.html import generate_html, render_html
from nessus_organiser.reporting.markdown import build_report_sections


def plugin(plugin_id: str, name: str) -> PluginFinding:
    return PluginFinding(
        plugin_id=plugin_id, plugin_name=name, host="host.test", port=0,
        protocol="tcp", service="", severity="High", plugin_output="",
    )


def copy_payloads(report: str) -> dict[str, str]:
    return {
        label: unescape(text)
        for label, text in re.findall(
            r'aria-label="Copy (.*?) Markdown".*?<textarea class="copy-text" hidden>(.*?)</textarea>',
            report, re.S,
        )
    }


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

    def test_grouped_reports_have_matching_sections_and_copy_content(self) -> None:
        content = load_tls_content()
        plugins = [plugin("104743", "TLS 1.0"), plugin("53360", "DH key validation")]
        findings = build_findings(organise_tls(plugins), content, build_evidence)
        findings = [analyse_tls_finding(f, "internal", content) for f in findings]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tls.html"
            generate_report(findings, path, content["title"], grouped=True, show_severity=True)
            report = path.read_text(encoding="utf-8")
        for heading in ("Finding", "Remediation", "Severity", "References"):
            self.assertIn(f"<h2>{heading}</h2>", report)
        for finding in findings:
            self.assertEqual(report.count(f"<h3>{finding.title}</h3>"), 3)
        self.assertIn("Severity justifications are review templates", report)
        self.assertIn("Verify the assessment context", report)
        self.assertIn("### Weak Diffie\\-Hellman Key Validation", report)
        self.assertIn('data-group="weak_dh_key_validation"', report)

    def test_tls_severity_justifications_are_internal_only(self) -> None:
        content = load_tls_content()
        plugins = [plugin("104743", "TLS 1.0")]
        for scope, severity in (("internal", "Informational"), ("external", "Low")):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as directory:
                findings = build_findings(organise_tls(plugins), content, build_evidence)
                finding = analyse_tls_finding(findings[0], scope, content)
                self.assertEqual(finding.severity, severity)
                path = Path(directory) / "tls.html"
                generate_report([finding], path, content["title"], grouped=True, show_severity=True)
                report = path.read_text(encoding="utf-8")
                self.assertIn(f"<strong>Severity:</strong> {severity}", report)
                self.assertEqual("Severity justifications are review templates" in report, scope == "internal")
                self.assertEqual(
                    "does not necessarily imply immediate exploitability" in " ".join(report.split()),
                    scope == "internal",
                )

    def test_section_copies_omit_section_headings_but_keep_nested_titles(self) -> None:
        content = load_tls_content()
        findings = build_findings(
            organise_tls([plugin("104743", "TLS")]), content, build_evidence
        )
        finding = analyse_tls_finding(findings[0], "internal", content)
        sections = build_report_sections([finding], content["title"], "Introduction.")
        copies = copy_payloads(render_html(sections, grouped=True, show_severity=True))
        for label in ("finding", "remediation", "severity", "references"):
            self.assertFalse(copies[label].startswith(("# Finding", "## Finding", "# Remediation", "## Remediation", "# Severity", "## Severity", "# References", "## References")))
        for label in ("finding", "remediation"):
            self.assertIn("### Deprecated TLS 1.0 Protocol Support", copies[label])
        self.assertIn("### Deprecated TLS 1\\.0 Protocol Support", copies["severity"])
        self.assertIn("## Finding", copies["report"])
        self.assertIn("## Remediation", copies["report"])
        self.assertIn("## Severity", copies["report"])

    def test_card_copies_omit_finding_title_and_keep_closure_references(self) -> None:
        content = load_tls_content()
        findings = build_findings(
            organise_tls([plugin("104743", "TLS")]), content, build_evidence
        )
        finding = analyse_tls_finding(findings[0], "internal", content)
        sections = build_report_sections([finding], content["title"])
        copies = copy_payloads(render_html(sections))
        for label in ("technical commentary", "remediation", "references"):
            self.assertFalse(copies[label].startswith("#"), label)
        closure = copy_payloads(render_html(sections, closure_review=True))
        self.assertFalse(closure["closure justification"].startswith("#"))
        self.assertIn("#### References", closure["closure justification"])

    def test_patching_grouped_layout_has_no_severity_section(self) -> None:
        content = load_patch_management_content()
        findings = build_findings(
            {"missing_security_patches": [plugin("2", "Patch")]}, content
        )
        statistics = {
            "summary": {"legacy_vulnerabilities": 0, "patch_vulnerabilities": 1, "total_vulnerabilities": 1},
            "high_risk": {"legacy_vulnerabilities": 0, "patch_vulnerabilities": 1},
            "top_legacy_findings": [], "top_patch_findings": [("Patch", 9.0, 1, 100)],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "patch.html"
            generate_report(findings, path, content["title"], statistics=statistics, grouped=True)
            report = path.read_text(encoding="utf-8")
        self.assertIn("<h2>Finding</h2>", report)
        self.assertIn("<h2>Remediation</h2>", report)
        self.assertNotIn("<h2>Severity</h2>", report)
        self.assertEqual(report.count(f"<h3>{findings[0].title}</h3>"), 2)

    def test_tls_plugin_specific_content_does_not_claim_unrelated_issues(self) -> None:
        content = load_tls_content()
        cases = (
            ("53360", "weak_dh_key_validation", "Weak Diffie-Hellman Key Validation", "Logjam"),
            ("83875", "weak_dh_parameters", "Weak Diffie-Hellman Parameters Supported (Logjam)", "public value"),
            ("51893", "weak_cipher_suites", "Weak Cipher Suite Enforcement During Session Resumption", "supported one or more weak or deprecated"),
            ("42880", "deprecated_tls_support", "Insecure TLS Renegotiation Supported", "one or more deprecated TLS protocol versions"),
            ("20007", "deprecated_ssl_support", "Deprecated SSL Version Support", "Testing identified support for SSL 2.0 and SSL 3.0."),
        )
        for plugin_id, category, title, absent in cases:
            with self.subTest(plugin_id=plugin_id):
                findings = build_findings(
                    organise_tls([plugin(plugin_id, "Example")]), content, build_evidence
                )
                self.assertEqual(len(findings), 1)
                finding = analyse_tls_finding(findings[0], "internal", content)
                self.assertEqual(finding.category, category)
                self.assertEqual(finding.title, title)
                text = build_report_sections([finding], "TLS").commentary[0][1]
                self.assertNotIn(absent, text)
                self.assertTrue(finding.severity_justification)

    def test_requested_tls_plugins_have_scope_specific_ratings(self) -> None:
        groups = {
            "deprecated_ssl_support": ("20007", "78447", "78479", "89058"),
            "deprecated_tls_support": ("104743", "157288"),
            "weak_cipher_suites": ("42873", "51893", "65821", "81606"),
            "invalid_certificate_configuration": ("51192", "15901", "57582", "45410", "45411", "56284"),
            "weak_certificate_cryptography": ("35291", "69551", "60108", "86067"),
            "weak_dh_parameters": ("83875",),
            "weak_dh_key_validation": ("53360",),
            "anonymous_cipher_suites": ("31705",),
        }
        for category, plugin_ids in groups.items():
            for plugin_id in plugin_ids:
                for scope, severity in (("internal", "Informational"), ("external", "Low")):
                    with self.subTest(plugin_id=plugin_id, scope=scope):
                        content = load_tls_content()
                        findings = build_findings(
                            organise_tls([plugin(plugin_id, "Example")]), content, build_evidence
                        )
                        self.assertEqual(len(findings), 1)
                        finding = analyse_tls_finding(findings[0], scope, content)
                        self.assertEqual(finding.category, category)
                        expected = "High" if scope == "external" and plugin_id == "51893" else severity
                        self.assertEqual(finding.severity, expected)
                        self.assertEqual(bool(finding.severity_justification), scope == "internal")

    def test_tls_combined_cipher_and_renegotiation_content(self) -> None:
        content = load_tls_content()
        plugins = [plugin(id_, id_) for id_ in ("42873", "51893", "104743", "42880")]
        findings = build_findings(organise_tls(plugins), content, build_evidence)
        by_category = {
            f.category: analyse_tls_finding(f, "internal", content) for f in findings
        }
        ciphers = by_category["weak_cipher_suites"]
        self.assertIn("disabled cipher", ciphers.commentary)
        self.assertIn("weak or deprecated", ciphers.commentary)
        self.assertIn("session resumption", ciphers.severity_justification)
        self.assertIn("Modern clients", ciphers.severity_justification)
        tls = by_category["deprecated_tls_support"]
        self.assertIn("renegotiation", tls.commentary)
        self.assertIn("TLS 1.0", tls.severity_justification)
        self.assertIn("renegotiation", tls.severity_justification)

    def test_external_cipher_group_keeps_resumption_plugin_severity(self) -> None:
        content = load_tls_content()
        resumed = plugin("51893", "Session resumption")
        resumed.severity = "Medium"
        findings = build_findings(
            organise_tls([plugin("42873", "3DES"), resumed]), content, build_evidence
        )
        finding = analyse_tls_finding(findings[0], "external", content)
        self.assertEqual(finding.severity, "Medium")
        self.assertIsNone(finding.severity_justification)

    def test_non_html_output_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.md"
            with self.assertRaisesRegex(ValueError, "html"):
                generate_report([], path, "Example", introduction="Introduction.")
            self.assertFalse(path.exists())

    def test_existing_timestamped_report_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reports" / "report-20261123-123456-000000.html"
            path.parent.mkdir()
            path.write_text("existing", encoding="utf-8")
            first = generate_html([], path, "Example")
            second = generate_html([], path, "Example")
            self.assertEqual(path.read_text(encoding="utf-8"), "existing")
            self.assertEqual(first.name, "report-20261123-123456-000000-1.html")
            self.assertEqual(second.name, "report-20261123-123456-000000-2.html")
            self.assertIn("Example", first.read_text(encoding="utf-8"))
            self.assertIn("Example", second.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
