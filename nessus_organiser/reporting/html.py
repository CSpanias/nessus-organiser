"""Self-contained HTML report for offline review."""

from dataclasses import dataclass
from html import escape
from pathlib import Path

from markdown_it import MarkdownIt

from nessus_organiser.models.finding import Finding
from nessus_organiser.reporting.markdown import (
    ReportSections,
    _reflow_markdown,
    build_report_sections,
    escape_markdown_text,
    format_markdown,
)


@dataclass(slots=True)
class ReportTab:
    label: str
    sections: ReportSections
    closure_review: bool = False
    grouped: bool = False
    show_severity: bool = False
    references_in_remediation: bool = False


def _copy_controls(markdown: str, label: str) -> str:
    return (
        '<div class="copy-controls">'
        f'<button type="button" class="copy" aria-label="Copy {escape(label)} Markdown">'
        'Copy Markdown</button> <span class="status" aria-live="polite"></span>'
        f'<textarea class="copy-text" hidden>{escape(markdown)}</textarea></div>'
    )


def _render_content(
    sections: ReportSections, *, closure_review: bool = False,
    grouped: bool = False, show_severity: bool = False,
    references_in_remediation: bool = False,
    prefix: str = "",
) -> str:
    markdown = MarkdownIt("commonmark", {"html": False}).enable("table").disable("image")
    remediation = {finding.category: text for finding, text in sections.remediation}
    cards = []
    for finding, commentary in ([] if grouped else sections.commentary):
        label = "Closure Justification" if closure_review else "Technical Commentary"
        solution = remediation.get(finding.category)
        if closure_review:
            evidence = _reflow_markdown(finding.commentary_evidence).strip()
            justification = _reflow_markdown(finding.commentary).strip()
            detail = f'<details open><summary>{label}</summary>'
            if evidence:
                detail += markdown.render(evidence)
            if justification:
                detail += (
                    markdown.render(justification)
                    + _copy_controls(justification, "closure justification")
                )
            if solution:
                detail += markdown.render(solution.partition("\n\n")[2])
            if finding.references:
                references = "\n".join(
                    f"- [{reference}]({reference})"
                    for reference in sorted(set(finding.references))
                )
                detail += markdown.render("#### References\n\n" + references)
            detail += "</details>"
        else:
            detail = (
                f'<details open><summary>{label}</summary>'
                + _copy_controls(commentary.partition("\n\n")[2], label.lower())
                + markdown.render(commentary.partition("\n\n")[2])
                + "</details>"
            )
            if solution:
                detail += (
                    "<details><summary>Remediation</summary>"
                    + _copy_controls(solution.partition("\n\n")[2], "remediation")
                    + markdown.render(solution.partition("\n\n")[2])
                    + "</details>"
                )
        alternate_id = (
            f'<span class="badge">{escape(finding.alternate_id)}</span>'
            if finding.alternate_id else ""
        )
        cards.append(
            '<article class="finding">'
            f"<h3>{escape(finding.title)}</h3>"
            f'<span class="badge">{escape(finding.id)}</span>'
            + alternate_id
            + f'<span class="badge">{escape(finding.severity)}</span>'
            + detail + "</article>"
        )

    overview = markdown.render(sections.overview) if sections.overview else ""
    remediation_intro = (
        '<section class="panel"><h2>Remediation Guidance</h2>'
        + markdown.render(sections.remediation_introduction)
        + "</section>"
        if sections.remediation_introduction else ""
    )
    references = (
        '<section class="panel"><h2>References</h2>'
        + _copy_controls(sections.references, "references")
        + markdown.render(sections.references)
        + "</section>"
        if sections.references and not closure_review else ""
    )
    findings_content = "\n".join(cards) or '<p class="empty">No findings were generated.</p>'
    finding_count = len(sections.commentary)
    finding_word = "finding" if finding_count == 1 else "findings"
    search_controls = f"""
      <label for="{prefix}search">Search findings</label>
      <input id="{prefix}search" class="search" type="search" placeholder="Search findings">
      <p class="count" aria-live="polite">{finding_count} {finding_word}</p>
      <p class="no-matches" hidden>No findings match the search.</p>
    """
    if grouped:
        finding_text = "\n\n".join(
            ([sections.overview] if sections.overview else [])
            + [text for _, text in sections.commentary]
        )
        remediation_text = "\n\n".join(
            ([sections.remediation_introduction] if sections.remediation_introduction else [])
            + [text for _, text in sections.remediation]
        )
        nested_references = ""
        if references_in_remediation and sections.references:
            remediation_text += "\n\n### References\n\n" + sections.references
            nested_references = (
                "<div><h3>References</h3>"
                + _copy_controls(sections.references, "references")
                + markdown.render(sections.references)
                + "</div>"
            )
        severity_items = []
        severity_cards = []
        for finding, _ in (sections.commentary if show_severity else []):
            heading = f"### {escape_markdown_text(finding.title)}"
            ids = " ".join(sorted(
                {plugin.plugin_id for plugin in finding.affected_plugins}, key=int
            ))
            rating = f"**Severity:** {escape_markdown_text(finding.severity)}"
            justification = _reflow_markdown(finding.severity_justification).strip()
            severity_items.append("\n\n".join(
                part for part in (heading, ids, rating, justification) if part
            ))
            severity_cards.append(
                f'<article class="finding" data-group="{escape(finding.category, quote=True)}">'
                + markdown.render(heading)
                + (markdown.render(ids) + _copy_controls(ids, f"plugin IDs for {finding.title}")
                   if ids else "")
                + markdown.render(rating)
                + (markdown.render(justification)
                   + _copy_controls(justification, f"severity justification for {finding.title}")
                   if justification else "")
                + "</article>"
            )
        severity_text = "\n\n".join(severity_items)
        report_parts = [
            f"# {sections.title}", f"## Finding\n\n{finding_text}",
            f"## Remediation\n\n{remediation_text}",
        ]
        if show_severity:
            report_parts.append(f"## Severity\n\n{severity_text}")
        if sections.references and not references_in_remediation:
            report_parts.append(f"## References\n\n{sections.references}")

        def grouped_cards(items: list[tuple[Finding, str]]) -> str:
            return "\n".join(
                f'<article class="finding" data-group="{escape(finding.category, quote=True)}">'
                f"{markdown.render(text)}</article>"
                for finding, text in items
            )

        content = (
            _copy_controls("\n\n".join(report_parts), "report")
            + search_controls
            + '<section class="panel"><h2>Finding</h2>'
            + _copy_controls(finding_text, "finding")
            + overview + grouped_cards(sections.commentary) + "</section>"
            + '<section class="panel"><h2>Remediation</h2>'
            + _copy_controls(remediation_text, "remediation")
            + (markdown.render(sections.remediation_introduction)
               if sections.remediation_introduction else "")
            + grouped_cards(sections.remediation) + nested_references + "</section>"
        )
        if show_severity:
            content += (
                '<section class="panel"><h2>Severity</h2>'
                + "\n".join(severity_cards) + "</section>"
            )
        if not references_in_remediation:
            content += references
    else:
        content = (
            '<section class="panel"><h2>Report Overview</h2>'
            + ("" if closure_review else _copy_controls(format_markdown(sections), "report"))
            + overview
            + "</section>" + remediation_intro
            + f'<section aria-labelledby="{prefix}findings-heading">'
            + f'<h2 id="{prefix}findings-heading">Findings</h2>' + search_controls
            + f'<div>{findings_content}</div></section>'
            + references
        )
    return content


def _document(title: str, content: str) -> str:
    title = escape(title)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{ font-family: system-ui, sans-serif; color: #172033; background: #f3f6fa; }}
    body {{ margin: 0; }}
    header {{ padding: 2rem max(1rem, calc((100% - 1100px) / 2)); background: #10233f; color: white; }}
    header h1 {{ margin: 0; }}
    main {{ max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }}
    .panel, .finding {{ background: white; border: 1px solid #dce3ed; border-radius: .6rem; padding: 1rem; margin: 1rem 0; overflow-wrap: anywhere; }}
    .finding {{ border-left: 5px solid #607d9d; }}
    .finding h3 {{ margin: 0 0 .4rem; }}
    .badge {{ display: inline-block; margin: .25rem .4rem .5rem 0; padding: .15rem .5rem; border-radius: 1rem; background: #e8edf4; font-size: .82rem; }}
    details {{ margin: .75rem 0; padding: 1rem; border: 1px solid #dce3ed; border-radius: .6rem; }}
    summary {{ cursor: pointer; font-weight: 650; }}
    p, li {{ line-height: 1.55; }}
    input, button {{ padding: .6rem; border: 1px solid #9aa8bb; border-radius: .35rem; background: white; color: inherit; }}
    input {{ width: min(100%, 30rem); box-sizing: border-box; }}
    button {{ cursor: pointer; }}
    button:disabled {{ cursor: wait; opacity: .7; }}
    .copy-controls {{ margin: .75rem 0; }}
    .status, .count, footer {{ color: #53647b; }}
    [hidden] {{ display: none !important; }}
    .tabs {{ display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: 1rem; }}
    .tabs button[aria-selected="true"] {{ background: #10233f; color: white; }}
    .copy-buffer {{ position: fixed; left: -9999px; top: 0; }}
    .panel, details {{ overflow-x: auto; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #dce3ed; padding: .5rem; text-align: left; }}
    footer {{ margin: 2rem 0; font-size: .9rem; }}
  </style>
</head>
<body>
  <header><h1>{title}</h1><p>Local assessment report</p></header>
  <main>
    {content}
    <footer>Generated by Nessus Organiser. This report works offline and contains assessment data.</footer>
  </main>
  <script>
    for (const report of document.querySelectorAll(".report-content")) {{
      const cards = [...report.querySelectorAll(".finding")];
      const search = report.querySelector(".search");
      search.addEventListener("input", () => {{
        const query = search.value.trim().toLowerCase();
        const groups = new Set(cards.map((card, index) => card.dataset.group ?? String(index)));
        const matching = new Set(cards.filter(card => card.textContent.toLowerCase().includes(query))
          .map(card => card.dataset.group ?? String(cards.indexOf(card))));
        for (const card of cards) {{
          const group = card.dataset.group ?? String(cards.indexOf(card));
          card.hidden = !matching.has(group);
        }}
        report.querySelector(".count").textContent =
          `${{matching.size}} of ${{groups.size}} ${{groups.size === 1 ? "finding" : "findings"}}`;
        report.querySelector(".no-matches").hidden = matching.size > 0 || !groups.size;
      }});
    }}

    const tabs = [...document.querySelectorAll('[role="tab"]')];
    if (tabs.length) {{
      const selectTab = selected => {{
        for (const tab of tabs) {{
          const active = tab === selected;
          tab.setAttribute("aria-selected", String(active));
          tab.tabIndex = active ? 0 : -1;
          document.getElementById(tab.getAttribute("aria-controls")).hidden = !active;
        }}
      }};
      for (const tab of tabs) {{
        tab.addEventListener("click", () => selectTab(tab));
        tab.addEventListener("keydown", event => {{
          const index = tabs.indexOf(tab);
          let next;
          if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
          else if (event.key === "ArrowLeft") next = (index + tabs.length - 1) % tabs.length;
          else if (event.key === "Home") next = 0;
          else if (event.key === "End") next = tabs.length - 1;
          else return;
          event.preventDefault();
          selectTab(tabs[next]);
          tabs[next].focus();
        }});
      }}
      selectTab(tabs[0]);
      document.querySelector(".tabs").hidden = false;
    }}

    async function copyText(text) {{
      if (navigator.clipboard?.writeText && window.isSecureContext) {{
        await navigator.clipboard.writeText(text);
        return;
      }}
      const buffer = document.createElement("textarea");
      buffer.value = text;
      buffer.className = "copy-buffer";
      document.body.append(buffer);
      buffer.select();
      let copied;
      try {{ copied = document.execCommand("copy"); }}
      finally {{ buffer.remove(); }}
      if (!copied) throw new Error("Clipboard access is unavailable.");
    }}
    for (const controls of document.querySelectorAll(".copy-controls")) {{
      const button = controls.querySelector(".copy");
      const status = controls.querySelector(".status");
      button.addEventListener("click", async () => {{
        button.disabled = true;
        status.textContent = "Copying...";
        try {{
          await copyText(controls.querySelector(".copy-text").value);
          status.textContent = "Copied Markdown to clipboard.";
        }} catch {{
          status.textContent = "Copy failed. Select and copy the report text manually.";
        }} finally {{
          button.disabled = false;
        }}
      }});
    }}
  </script>
</body>
</html>
"""


def render_html(
    sections: ReportSections, *, closure_review: bool = False,
    grouped: bool = False, show_severity: bool = False,
    references_in_remediation: bool = False,
) -> str:
    """Render a report without external assets or network access."""
    content = _render_content(
        sections, closure_review=closure_review, grouped=grouped,
        show_severity=show_severity, references_in_remediation=references_in_remediation,
    )
    return _document(sections.title, f'<div class="report-content">{content}</div>')


def render_combined_html(tabs: list[ReportTab]) -> str:
    """Render independent reports in one offline tabbed document."""
    buttons = []
    panels = []
    for index, tab in enumerate(tabs):
        prefix = f"report-{index}-"
        label = escape(tab.label)
        buttons.append(
            f'<button type="button" role="tab" id="{prefix}tab" '
            f'aria-controls="{prefix}panel" aria-selected="false">{label}</button>'
        )
        content = _render_content(
            tab.sections, closure_review=tab.closure_review, grouped=tab.grouped,
            show_severity=tab.show_severity,
            references_in_remediation=tab.references_in_remediation, prefix=prefix,
        )
        panels.append(
            f'<section class="report-content" role="tabpanel" id="{prefix}panel" '
            f'aria-labelledby="{prefix}tab"><h2>{escape(tab.sections.title)}</h2>'
            f"{content}</section>"
        )
    navigation = (
        '<nav class="tabs" role="tablist" aria-label="Reports" hidden>'
        + "".join(buttons) + "</nav>"
    )
    return _document("Nessus Organiser Report", navigation + "".join(panels))


def generate_html(
    findings: list[Finding],
    output_path: Path,
    title: str,
    introduction: str | None = None,
    remediation_introduction: str | None = None,
    statistics: dict | None = None,
    ithc: bool = False,
    closure_review: bool = False,
    grouped: bool = False,
    show_severity: bool = False,
    references_in_remediation: bool = False,
) -> Path:
    sections = build_report_sections(
        findings, title, introduction, remediation_introduction, statistics, ithc
    )
    report = render_html(
        sections, closure_review=closure_review, grouped=grouped,
        show_severity=show_severity, references_in_remediation=references_in_remediation,
    )
    return write_html(report, output_path)


def write_html(report: str, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    candidate = output_path
    suffix = 0
    while True:
        try:
            file = candidate.open("x", encoding="utf-8")
        except FileExistsError:
            suffix += 1
            candidate = output_path.with_name(
                f"{output_path.stem}-{suffix}{output_path.suffix}"
            )
            continue
        with file:
            file.write(report)
        return candidate
