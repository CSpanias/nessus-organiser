"""Generate scope-specific suggestions for findings to review for closure."""

from pathlib import Path

from rich.console import Console

from nessus_organiser.common.progress import load_scan
from nessus_organiser.content.loader import load_closure_content
from nessus_organiser.findings.factory import build_finding
from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.reporting import AnalysisReport, generate_analysis_report, print_report_summary


def run(
    nessus_file: Path, output_file: Path, scope: str, csacyber: bool = False,
    plugin_findings: list[PluginFinding] | None = None,
    console: Console | None = None,
) -> None:
    if scope not in ("internal", "external"):
        raise ValueError(f"Unknown assessment scope: {scope}")
    if plugin_findings is None:
        content = load_closure_content()
        if not any(scope in definition for definition in content["plugins"].values()):
            _report_not_generated(f"No closure rules are defined for {scope} scope.", console)
            return
        plugin_findings = load_scan(nessus_file)
    report = analyse(plugin_findings, scope, csacyber, console)
    if report is None:
        return
    generated = generate_analysis_report(report, output_file)
    print_report_summary(report, generated, console)


def analyse(
    plugin_findings: list[PluginFinding], scope: str, csacyber: bool = False,
    console: Console | None = None,
) -> AnalysisReport | None:
    if scope not in ("internal", "external"):
        raise ValueError(f"Unknown assessment scope: {scope}")
    content = load_closure_content()
    definitions = {
        plugin_id: definition
        for plugin_id, definition in content["plugins"].items()
        if scope in definition
    }
    if not definitions:
        _report_not_generated(f"No closure rules are defined for {scope} scope.", console)
        return

    grouped: dict[str, list[PluginFinding]] = {plugin_id: [] for plugin_id in definitions}
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
        hosts = {plugin.host or "(unknown host)" for plugin in matches}
        finding.commentary_evidence = (
            f"Nessus plugin {plugin_id} was identified on {len(hosts):,} "
            f"unique {'host' if len(hosts) == 1 else 'hosts'}."
        )
        findings.append(finding)

    if not findings:
        return

    return AnalysisReport(
        label="Closure",
        findings=findings,
        title=content["title"],
        introduction=f"Assessment scope: {scope}.\n\n{content['introduction']}",
        closure_review=True,
        summary_title="Closure Review Summary",
        summary_rows=[
            ("Assessment Scope", scope),
            ("Matched Plugins", str(len(findings))),
            ("Affected Hosts", str(len({plugin.host for group in grouped.values() for plugin in group}))),
        ],
    )


def _report_not_generated(reason: str, console: Console | None = None) -> None:
    message = f"{reason} No closure report was generated."
    (console or Console(stderr=True)).print(message, markup=False)
