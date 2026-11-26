"""Interactive progress for loading Nessus scans."""

from collections.abc import Collection
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TaskProgressColumn,
    TextColumn,
)

from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.parsing.nessus import load_nessus


def report_progress(*, transient: bool = True, spinner: bool = True) -> Progress:
    console = Console()
    return Progress(
        *((SpinnerColumn(),) if spinner else ()),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=transient,
        disable=not console.is_terminal,
    )


def load_scan(
    path: Path,
    exclude_ips: Collection[str] | None = None,
) -> list[PluginFinding]:
    with report_progress() as progress:
        task = progress.add_task("Reading Nessus scan...", total=None)

        def update(completed: int, total: int) -> None:
            progress.update(
                task, description="Processing hosts...", total=total, completed=completed
            )

        if exclude_ips:
            return load_nessus(path, on_progress=update, exclude_ips=exclude_ips)
        return load_nessus(path, on_progress=update)
