import unittest

from nessus_organiser.organising.ssh import organise_ssh, build_evidence
from nessus_organiser.models.plugin import PluginFinding


def make_finding(plugin_id: str) -> PluginFinding:
    return PluginFinding(
        plugin_id=plugin_id,
        plugin_name="Test finding",
        host="example.test",
        port=None,
        protocol=None,
        service=None,
        severity="Informational",
        plugin_output="",
    )


class SSHOrganiserTests(unittest.TestCase):
    def test_organises_ssh_plugins_into_categories(self) -> None:
        findings = [
            make_finding("187315"),
            make_finding("71049"),
            make_finding("99999"),
        ]

        grouped = organise_ssh(findings)

        self.assertEqual(
            set(grouped),
            {"terrapin_prefix_truncation", "weak_mac_algorithms"},
        )
        self.assertEqual(grouped["terrapin_prefix_truncation"], [findings[0]])
        self.assertEqual(grouped["weak_mac_algorithms"], [findings[1]])

    def test_build_evidence_uses_plugin_specific_statements(self) -> None:
        evidence = build_evidence([make_finding("90317")])

        self.assertEqual(
            evidence,
            ["Weak SSH cipher algorithms supported (Arcfour/RC4)"],
        )


if __name__ == "__main__":
    unittest.main()