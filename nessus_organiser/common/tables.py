"""
nessus_organiser.common.tables

Helpers for rendering Rich-formatted tables to the terminal.
"""

from rich import box
from rich.console import Console
from rich.table import Table


def print_summary_table(
    title: str,
    rows: list[tuple[str, str]],
    console: Console | None = None,
) -> None:
    """
    Print a summary table to the terminal.

    Args:
        title:
            Title displayed above the table.

        rows:
            Table rows represented as Metric/Value pairs.
    """

    table = Table(
        title=title,
        box=box.ROUNDED,
        header_style="bold",
    )

    table.add_column("Metric", no_wrap=True, style="bold")
    table.add_column("Value", justify="right", overflow="fold")

    for metric, value in rows:

        table.add_row(metric, value)

    (console or Console()).print(table)


def print_table(
    title: str,
    columns: list[str],
    rows: list[tuple],
) -> None:
    """
    Print a multi-column table to the terminal.

    Args:
        title:
            Title displayed above the table.

        columns:
            Column headings.

        rows:
            Table rows.
    """

    table = Table(
        title=title,
        box=box.ROUNDED,
        header_style="bold",
    )

    for column in columns:
        table.add_column(column)

    for row in rows:
        table.add_row(*[str(cell) for cell in row])

    Console().print(table)