"""Generate scope-specific suggestions for findings to review for closure."""

from pathlib import Path

from rich.console import Console

from nessus_organiser.common.tables import print_summary_table
from nessus_organiser.common.progress import load_scan
from nessus_organiser.content.loader import load_closure_content
from nessus_organiser.findings.factory import build_finding
from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.reporting.html import generate_html
from nessus_organiser.reporting.markdown import escape_markdown_text


def run(
    nessus_file: Path, output_file: Path, scope: str, csacyber: bool = False,
    plugin_findings: list[PluginFinding] | None = None,
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
        _report_not_generated(f"No closure rules are defined for {scope} scope.")
        return

    grouped: dict[str, list[PluginFinding]] = {plugin_id: [] for plugin_id in definitions}
    if plugin_findings is None:
        plugin_findings = load_scan(nessus_file)
    for plugin in plugin_findings:
        if plugin.plugin_id in grouped:
            grouped[plugin.plugin_id].append(plugin)

    findings = []
    for plugin_id, matches in grouped.items():
        if not matches:
            continue
        definition = definitions[plugin_id]
        scope_content = definition[scope]
        finding = build_finding(
            category=plugin_id,
            findings=matches,
            definition={
                "id": f"Nessus {plugin_id}",
                "title": definition["title"],
                "severity": "Review",
                **scope_content,
            },
        )
        if csacyber and definition.get("platform_id"):
            finding.alternate_id = f"SureCloud {definition['platform_id']}"
        hosts = sorted({plugin.host or "(unknown host)" for plugin in matches})
        finding.commentary_evidence = (
            f"Nessus plugin {plugin_id} was identified on {len(hosts):,} "
            f"unique {'host' if len(hosts) == 1 else 'hosts'}:\n\n"
            + "\n".join(f"- {escape_markdown_text(host)}" for host in hosts)
        )
        findings.append(finding)

    if not findings:
        _report_not_generated("No closure-review plugins were found.")
        return

    generated = generate_html(
        findings=findings,
        output_path=output_file,
        title=content["title"],
        introduction=f"Assessment scope: {scope}.\n\n{content['introduction']}",
        closure_review=True,
    )
    print()
    print_summary_table(
        title="Closure Review Summary",
        rows=[
            ("Assessment Scope", scope),
            ("Matched Plugins", str(len(findings))),
            ("Affected Hosts", str(len({plugin.host for group in grouped.values() for plugin in group}))),
            ("Output Directory", str(generated.parent)),
            ("Output File", generated.name),
        ],
    )


def _report_not_generated(reason: str) -> None:
    message = f"{reason} No closure report was generated."
    Console(stderr=True).print(message, markup=False)
