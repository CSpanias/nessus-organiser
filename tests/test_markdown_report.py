import unittest

from nessus_organiser.models.finding import Finding
from nessus_organiser.reporting.markdown import (
    _reflow_markdown,
    build_report_sections,
    format_markdown,
)


class MarkdownReportTests(unittest.TestCase):
    def test_summary_explains_host_plugin_deduplication(self) -> None:
        statistics = {
            "summary": {
                "legacy_vulnerabilities": 1,
                "patch_vulnerabilities": 2,
                "total_vulnerabilities": 3,
            },
            "severity_distribution": [
                ("Critical", 1, 33.33),
                ("High", 1, 33.33),
                ("Medium", 1, 33.33),
                ("Low", 0, 0),
            ],
        }

        report = format_markdown(build_report_sections(
            findings=[],
            title="Patch Management Review",
            statistics=statistics,
        ))

        severity_table = report.index(
            "| Severity | Count | Percentage of Total Vulnerabilities |"
        )
        summary_table = report.index("| Metric | Value |")
        self.assertLess(severity_table, summary_table)
        self.assertIn("| Critical | 1 | 33.33% |", report)
        self.assertIn("| High | 1 | 33.33% |", report)
        self.assertIn("| Medium | 1 | 33.33% |", report)
        self.assertNotIn("| Low |", report)
        self.assertIn("**Note**:", report)
        self.assertIn(
            "Counts are deduplicated by host and Nessus plugin ID.",
            report,
        )
        self.assertIn(
            "A finding detected on multiple ports of the same host is counted once;",
            report,
        )
        self.assertIn(
            "the same plugin on different hosts is counted separately.",
            report,
        )

    def test_category_sections_use_their_own_severity_distributions(self) -> None:
        legacy = Finding(
            id="LEG", title="Unsupported Software",
            category="unsupported_software", severity="High",
            instances=1, hosts=1, services=1,
        )
        patch = Finding(
            id="PATCH", title="Missing Security Patches",
            category="missing_security_patches", severity="High",
            instances=1, hosts=1, services=1,
        )
        statistics = {
            "summary": {
                "legacy_vulnerabilities": 1,
                "patch_vulnerabilities": 1,
                "total_vulnerabilities": 2,
            },
            "severity_distribution": [
                ("Critical", 0, 0),
                ("High", 2, 100.0),
                ("Medium", 0, 0),
                ("Low", 0, 0),
            ],
            "legacy_severity_distribution": [
                ("Critical", 0, 0),
                ("High", 1, 100.0),
                ("Medium", 0, 0),
                ("Low", 0, 0),
            ],
            "patch_severity_distribution": [
                ("Critical", 0, 0),
                ("High", 0, 0),
                ("Medium", 0, 0),
                ("Low", 1, 100.0),
            ],
            "top_legacy_findings": [],
            "top_patch_findings": [],
        }

        sections = build_report_sections(
            findings=[legacy, patch],
            title="Patch Management Review",
            statistics=statistics,
        )
        by_category = {
            finding.category: commentary
            for finding, commentary in sections.commentary
        }

        self.assertIn(
            "| Severity | Count | Percentage of Legacy Vulnerabilities |",
            by_category["unsupported_software"],
        )
        self.assertIn("| High | 1 | 100.0% |", by_category["unsupported_software"])
        self.assertNotIn("| Low |", by_category["unsupported_software"])
        self.assertIn(
            "| Severity | Count | Percentage of Patch Vulnerabilities |",
            by_category["missing_security_patches"],
        )
        self.assertIn("| Low | 1 | 100.0% |", by_category["missing_security_patches"])
        self.assertNotIn("| High |", by_category["missing_security_patches"])


class ReflowMarkdownTests(unittest.TestCase):
    def test_joins_wrapped_prose_into_single_paragraph(self) -> None:
        text = (
            "The assessment identified a number of weaknesses affecting the "
            "transport\nlayer security (TLS) configuration of exposed services."
        )

        self.assertEqual(
            _reflow_markdown(text),
            "The assessment identified a number of weaknesses affecting the "
            "transport layer security (TLS) configuration of exposed services.",
        )

    def test_preserves_paragraph_separation(self) -> None:
        text = "First paragraph.\n\nSecond paragraph."

        self.assertEqual(
            _reflow_markdown(text),
            "First paragraph.\n\nSecond paragraph.",
        )

    def test_preserves_bullet_lists_and_continuations(self) -> None:
        text = (
            "Apply updates. In addition:\n\n"
            "- Implement a formal patch management process covering operating\n"
            "  systems, applications, and third-party software.\n"
            "- Monitor vendor security advisories for newly released updates."
        )

        self.assertEqual(
            _reflow_markdown(text),
            "Apply updates. In addition:\n\n"
            "- Implement a formal patch management process covering operating "
            "systems, applications, and third-party software.\n"
            "- Monitor vendor security advisories for newly released updates.",
        )

    def test_preserves_indented_bullet_lists(self) -> None:
        text = (
            "In addition:\n\n"
            "  - Review all externally and internally exposed services for "
            "legacy\n"
            "    protocol support.\n"
            "  - Ensure that only secure TLS versions are permitted."
        )

        self.assertEqual(
            _reflow_markdown(text),
            "In addition:\n\n"
            "  - Review all externally and internally exposed services for "
            "legacy protocol support.\n"
            "  - Ensure that only secure TLS versions are permitted.",
        )

    def test_preserves_headings(self) -> None:
        text = "#### Certificate Expiry\n\nThe certificate had expired."

        self.assertEqual(
            _reflow_markdown(text),
            "#### Certificate Expiry\n\nThe certificate had expired.",
        )


if __name__ == "__main__":
    unittest.main()
