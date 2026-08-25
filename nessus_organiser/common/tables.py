"""
nessus_organiser.common.tables

Helpers for rendering Rich-formatted tables to the terminal.
"""

from rich.console import Console
from rich.table import Table


def print_summary_table(
    title: str,
    rows: list[tuple[str, str]],
) -> None:
    """
    Print a summary table to the terminal.

    Args:
        title:
            Title displayed above the table.

        rows:
            Table rows represented as Metric/Value pairs.
    """

    table = Table(title=title)

    table.add_column("Metric")
    table.add_column("Value", justify="right")

    for metric, value in rows:

        table.add_row(metric, value)

    Console().print(table)