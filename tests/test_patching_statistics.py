import unittest

from nessus_organiser.analysis.patching import build_patch_management_statistics
from nessus_organiser.models.plugin import PluginFinding


def plugin(plugin_id: str, host: str, score: float, port: int) -> PluginFinding:
    return PluginFinding(
        plugin_id=plugin_id,
        plugin_name=f"Plugin {plugin_id}",
        host=host,
        port=port,
        protocol="tcp",
        service="https",
        severity="High",
        plugin_output="",
        cvss3_base_score=score,
    )


class PatchManagementStatisticsTests(unittest.TestCase):
    def test_builds_overall_and_category_severity_distributions(self) -> None:
        statistics = build_patch_management_statistics({
            "unsupported_software": [
                plugin("300", "legacy-high", 8.0, 0),
                plugin("301", "legacy-low", 2.0, 0),
            ],
            "missing_security_patches": [
                plugin("100", "patch-critical", 9.5, 443),
                plugin("100", "patch-critical", 9.5, 8443),
                plugin("200", "patch-medium", 5.0, 0),
            ],
        })

        self.assertEqual(
            statistics["severity_distribution"],
            [
                ("Critical", 1, 25.0),
                ("High", 1, 25.0),
                ("Medium", 1, 25.0),
                ("Low", 1, 25.0),
            ],
        )
        self.assertEqual(
            statistics["legacy_severity_distribution"],
            [
                ("Critical", 0, 0.0),
                ("High", 1, 50.0),
                ("Medium", 0, 0.0),
                ("Low", 1, 50.0),
            ],
        )
        self.assertEqual(
            statistics["patch_severity_distribution"],
            [
                ("Critical", 1, 50.0),
                ("High", 0, 0.0),
                ("Medium", 1, 50.0),
                ("Low", 0, 0.0),
            ],
        )


if __name__ == "__main__":
    unittest.main()
