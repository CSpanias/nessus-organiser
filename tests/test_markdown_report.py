import tempfile
import unittest
from pathlib import Path

from nessus_organiser.reporting.markdown import generate_markdown, _reflow_markdown


class MarkdownReportTests(unittest.TestCase):
    def test_summary_explains_host_plugin_deduplication(self) -> None:
        statistics = {
            "summary": {
                "legacy_vulnerabilities": 1,
                "patch_vulnerabilities": 2,
                "total_vulnerabilities": 3,
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.md"
            generate_markdown(
                findings=[],
                output_path=output_path,
                title="Patch Management Review",
                statistics=statistics,
            )

            report = output_path.read_text(encoding="utf-8")

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
