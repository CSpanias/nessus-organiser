"""Generate scope-specific suggestions for findings to review for closure."""

from pathlib import Path

from rich.console import Console

from nessus_organiser.common.tables import print_summary_table
from nessus_organiser.content.loader import load_closure_content
from nessus_organiser.findings.factory import build_finding
from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.parsing.nessus import load_nessus
from nessus_organiser.reporting.html import generate_html
from nessus_organiser.reporting.markdown import escape_markdown_text


def run(
    nessus_file: Path, output_file: Path, scope: str, csacyber: bool = False,
) -> None:
    if scope not in ("internal", "external"):
        raise ValueError(f"Unknown assessment scope: {scope}")
    content = load_closure_content()
    definitions = {
        plugin_id: definition
        for plugin_id, definition in content["plugins"].items()
        if scope in definition
    }
    if not definitions:
        _report_not_generated(output_file, f"No closure rules are defined for {scope} scope.")
        return

    grouped: dict[str, list[PluginFinding]] = {plugin_id: [] for plugin_id in definitions}
    for plugin in load_nessus(nessus_file):
        if plugin.plugin_id in grouped:
            grouped[plugin.plugin_id].append(plugin)

    findings = []
    for plugin_id, matches in grouped.items():
        if not matches:
            continue
        definition = definitions[plugin_id]
        scope_content = definition[scope]
        finding_id = f"Nessus {plugin_id}"
        if csacyber and definition.get("platform_id"):
            finding_id += f" | {definition['platform_id']}"
        finding = build_finding(
            category=plugin_id,
            findings=matches,
            definition={
                "id": finding_id,
                "title": definition["title"],
                "severity": "Review",
                **scope_content,
            },
        )
        hosts = sorted({plugin.host or "(unknown host)" for plugin in matches})
        finding.commentary_evidence = (
            f"Nessus plugin {plugin_id} was identified on {len(hosts):,} "
            f"unique {'host' if len(hosts) == 1 else 'hosts'}:\n\n"
            + "\n".join(f"- {escape_markdown_text(host)}" for host in hosts)
        )
        findings.append(finding)

    if not findings:
        _report_not_generated(output_file, "No closure-review plugins were found.")
        return

    generate_html(
        findings=findings,
        output_path=output_file,
        title=content["title"],
        introduction=f"Assessment scope: {scope}.\n\n{content['introduction']}",
    )
    print()
    print_summary_table(
        title="Closure Review Summary",
        rows=[
            ("Assessment Scope", scope),
            ("Matched Plugins", str(len(findings))),
            ("Affected Hosts", str(len({plugin.host for group in grouped.values() for plugin in group}))),
            ("Output File", str(output_file)),
        ],
    )


def _report_not_generated(output_file: Path, reason: str) -> None:
    message = f"{reason} No closure report was generated."
    if output_file.exists():
        message += f" Existing report '{output_file}' was not updated."
    Console(stderr=True).print(message, markup=False)
