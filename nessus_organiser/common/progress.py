"""Interactive progress for loading Nessus scans."""

from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TaskProgressColumn,
    TextColumn,
)

from nessus_organiser.models.plugin import PluginFinding
from nessus_organiser.parsing.nessus import load_nessus


def report_progress() -> Progress:
    console = Console()
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=True,
        disable=not console.is_terminal,
    )


def load_scan(path: Path) -> list[PluginFinding]:
    with report_progress() as progress:
        task = progress.add_task("Reading Nessus scan...", total=None)

        def update(completed: int, total: int) -> None:
            progress.update(
                task, description="Processing hosts...", total=total, completed=completed
            )

        return load_nessus(path, on_progress=update)
