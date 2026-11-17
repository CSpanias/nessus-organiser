import tempfile
import unittest
from pathlib import Path

from nessus_organiser.reporting.markdown import generate_markdown


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


if __name__ == "__main__":
    unittest.main()
