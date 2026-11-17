import unittest

from nessus_organiser.classifiers.patching import is_patch_management
from nessus_organiser.organising.patching import organise_patch_management
from nessus_organiser.models.plugin import PluginFinding


def make_finding(solution: str, plugin_id: str = "1") -> PluginFinding:
    return PluginFinding(
        plugin_id=plugin_id,
        plugin_name="Test finding",
        host="example.test",
        port=None,
        protocol=None,
        service=None,
        severity="High",
        plugin_output="",
        solution=solution,
    )


class PatchManagementClassifierTests(unittest.TestCase):
    def test_recognises_firmware_and_runtime_update_recommendations(self) -> None:
        solutions = (
            "Upgrade firmware of HP Integrated Lights-Out to 2.53 or later.",
            "Upgrade firmware to 2.80 or later.",
            "Update .NET Core, remove vulnerable packages and refer to vendor advisory.",
            "Update ASP.NET Core, remove vulnerable packages and refer to vendor advisory.",
            "Update to .NET Core 8.0.26 or later.",
        )

        for solution in solutions:
            with self.subTest(solution=solution):
                self.assertTrue(is_patch_management(make_finding(solution)))

    def test_does_not_classify_unrelated_solution_wording(self) -> None:
        self.assertFalse(
            is_patch_management(make_finding("Review the vendor advisory."))
        )

    def test_jms_appender_finding_is_organised_as_legacy(self) -> None:
        finding = make_finding(
            "Upgrade to Apache Log4j version 2.16.0 or later since 1.x is end of life.",
            plugin_id="156103",
        )

        grouped = organise_patch_management([finding]).grouped_findings

        self.assertEqual(grouped["unsupported_software"], [finding])
        self.assertEqual(grouped["missing_security_patches"], [])


if __name__ == "__main__":
    unittest.main()
