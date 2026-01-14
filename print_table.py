from rich.console import Console
from rich.table import Table

console = Console()

def print_table(report):
    table = Table(show_header=True, header_style="bold cyan", box=None)
    table.add_column("IP", style="magenta", no_wrap=True)
    table.add_column("Requests", style="white")
    table.add_column("AdminRequests", style="white")
    table.add_column("FailedLogins", style="white")
    table.add_column("AbuseScore", style="magenta")
    table.add_column("VT", style="magenta")
    table.add_column("Country", style="white")
    table.add_column("Risk", justify="right")
    table.add_column("Score", justify="right")
    for row in report:
        risk_style = "bold red" if row["Risk"] == "HIGH" else "bold yellow" if row["Risk"] == "MEDIUM" else "green"

        table.add_row(
            row["IP"],
            str(row["Requests"]),
            str(row.get("AdminRequests", 0)),
            str(row.get("FailedLogins", 0)),
            str(row.get("AbuseScore", 0)),
            str(row.get("VT", 0)),
            row["Country"],
            f"[{risk_style}]{row['Risk']}[/]",
            str(row["Score"])
        )
    console.print(table)