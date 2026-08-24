"""Rich console output formatting for BBMD Manager CLI."""

from typing import Dict, List, Optional, Tuple

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text

from .models import BBMD, AuditEntry, BBMDNetwork, BDTEntry, Snapshot


class BBMDConsole:
    """Console wrapper for BBMD Manager with consistent styling."""

    def __init__(self, verbose: bool = False):
        self.console = Console()
        self.verbose = verbose

    def info(self, message: str):
        """Print info message."""
        self.console.print(f"[blue]>[/blue] {message}")

    def success(self, message: str):
        """Print success message."""
        self.console.print(f"[green]✓[/green] {message}")

    def warning(self, message: str):
        """Print warning message."""
        self.console.print(f"[yellow]![/yellow] {message}")

    def error(self, message: str):
        """Print error message."""
        self.console.print(f"[red]✗[/red] {message}")

    def verbose_log(self, message: str):
        """Print message only in verbose mode."""
        if self.verbose:
            self.console.print(f"[dim]{message}[/dim]")

    def debug(self, message: str):
        """Print debug message."""
        self.console.print(f"[dim][DEBUG][/dim] {message}")

    def empty_state(self, message: str):
        """Print empty state message."""
        self.console.print(f"[dim]{message}[/dim]")

    def raw(self, message: str):
        """Print raw message (for JSON output)."""
        self.console.print(message, highlight=False)

    def print(self, *args, **kwargs):
        """Pass-through to console.print for direct Rich output."""
        self.console.print(*args, **kwargs)

    def confirm(self, message: str) -> bool:
        """Prompt for confirmation using Rich Confirm."""
        return Confirm.ask(f"[bold yellow]{message}[/bold yellow]")

    def progress_status(self, description: str):
        """Return a status context manager for progress indication."""
        return self.console.status(f"[bold blue]{description}[/bold blue]", spinner="dots")


class OutputFormatter:
    """Factory for creating formatted Rich tables and panels."""

    @staticmethod
    def bbmd_status_table(bbmds: Dict[str, BBMD]) -> Table:
        """Create table for status command output."""
        table = Table(
            title=f"BBMD Network Status ({len(bbmds)} BBMDs)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("BBMD Address", style="cyan", no_wrap=True)
        table.add_column("BDT Entries", justify="right")
        table.add_column("Broadcast Subnet", style="green", no_wrap=True)
        table.add_column("Last Read", style="dim")
        table.add_column("Peers")

        for addr in sorted(bbmds.keys()):
            bbmd = bbmds[addr]
            last_read = bbmd.last_read.strftime("%Y-%m-%d %H:%M:%S") if bbmd.last_read else "-"
            peers = ", ".join(e.address for e in bbmd.bdt) or "(empty)"
            table.add_row(addr, str(len(bbmd.bdt)), bbmd.subnet or "-", last_read, peers)

        return table

    @staticmethod
    def bdt_table(
        entries: List[BDTEntry], address: str, subnet: Optional[str] = None
    ) -> Table:
        """Create table for single BBMD's BDT."""
        table = Table(
            title=f"BDT for {address}" + (f" (broadcast subnet {subnet})" if subnet else ""),
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Entry Address", style="cyan")

        if entries:
            for entry in entries:
                table.add_row(entry.address)
        else:
            table.add_row("[dim](empty)[/dim]")

        return table

    @staticmethod
    def discovery_table(bbmds: Dict[str, BBMD]) -> Table:
        """Create summary table for walk/discovery results."""
        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("Address", style="cyan")
        table.add_column("Entries", justify="right", style="dim")
        table.add_column("Broadcast Subnet", style="green")

        for addr in sorted(bbmds.keys()):
            bbmd = bbmds[addr]
            table.add_row(addr, f"{len(bbmd.bdt)} BDT entries", bbmd.subnet or "-")

        return table

    @staticmethod
    def links_table(links: List[Tuple[str, str]], network: BBMDNetwork) -> Table:
        """Create table for links command output."""
        table = Table(
            title=f"Network Links ({len(links)} directed)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Source", style="cyan")
        table.add_column("Direction", justify="center")
        table.add_column("Target", style="cyan")
        table.add_column("Type", style="dim")

        shown_bidirectional: set = set()
        for source, target in sorted(links):
            pair = tuple(sorted([source, target]))
            is_bidirectional = network.has_bidirectional_link(source, target)

            if is_bidirectional:
                if pair not in shown_bidirectional:
                    table.add_row(source, "[green]<->[/green]", target, "[green]bidirectional[/green]")
                    shown_bidirectional.add(pair)
            else:
                table.add_row(source, "[yellow]-->[/yellow]", target, "[yellow]unidirectional[/yellow]")

        return table

    @staticmethod
    def audit_table(entries: List[AuditEntry]) -> Table:
        """Create table for audit log output."""
        table = Table(
            title=f"Audit Log ({len(entries)} entries)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Timestamp", style="dim")
        table.add_column("Action", style="yellow")
        table.add_column("BBMD", style="cyan")
        table.add_column("Details")
        table.add_column("Snapshot", style="dim")

        for entry in entries:
            ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            details = ", ".join(f"{k}={v}" for k, v in entry.details.items())
            table.add_row(ts, entry.action, entry.bbmd_address, details, entry.snapshot_id or "-")

        return table

    @staticmethod
    def snapshot_table(snapshots: List[Snapshot]) -> Table:
        """Create table for snapshots output."""
        table = Table(
            title=f"Available Snapshots ({len(snapshots)} shown)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Snapshot ID", style="cyan")
        table.add_column("Created", style="dim")
        table.add_column("Description")
        table.add_column("BBMDs", justify="right")

        for snapshot in snapshots:
            ts = snapshot.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            bbmd_count = len(snapshot.network_state.bbmds)
            table.add_row(snapshot.id, ts, snapshot.description, str(bbmd_count))

        return table

    @staticmethod
    def change_plan_panel(changes: List[dict], operation: str = "PROPOSED CHANGES") -> Panel:
        """Create panel for change plans (add-link, delete-link, delete-bbmd)."""
        content = Text()

        for change in changes:
            content.append("\nBBMD: ", style="bold")
            content.append(f"{change['bbmd']}\n", style="cyan")

            if change.get("action") == "clear_bdt":
                content.append("  Action: ", style="dim")
                content.append("Clear entire BDT\n", style="red bold")
            elif change.get("action") == "install_replacement":
                content.append("  Action: ", style="dim")
                content.append("Install copied replacement BDT\n", style="green bold")
            elif change.get("action") == "replace_entry":
                content.append("  Action: ", style="dim")
                content.append(
                    f"Replace {change['existing']} -> {change['replacement']}\n",
                    style="yellow",
                )
            elif change.get("adding"):
                content.append("  Action: ", style="dim")
                content.append(f"Add entry -> {change['adding']}\n", style="green")
            elif change.get("removing"):
                content.append("  Action: ", style="dim")
                content.append(f"Remove entry -> {change['removing']}\n", style="red")

            current = ", ".join(change["current_bdt"]) or "(empty)"
            new = ", ".join(change["new_bdt"]) or "(empty)"
            content.append("  Current BDT: ", style="dim")
            content.append(f"{current}\n")
            content.append("  New BDT:     ", style="dim")
            content.append(f"{new}\n", style="bold")

        content.append(f"\nTotal BBMDs to modify: {len(changes)}", style="bold yellow")

        return Panel(
            content,
            title=f"[bold yellow]{operation}[/bold yellow]",
            border_style="yellow",
            box=box.DOUBLE,
        )

    @staticmethod
    def diff_panel(diff_result: Dict, snapshot_id: str) -> Panel:
        """Create panel for diff output."""
        content = Text()

        if diff_result.get("added_bbmds"):
            content.append("\nAdded BBMDs:\n", style="bold green")
            for addr in diff_result["added_bbmds"]:
                content.append(f"  + {addr}\n", style="green")

        if diff_result.get("removed_bbmds"):
            content.append("\nRemoved BBMDs:\n", style="bold red")
            for addr in diff_result["removed_bbmds"]:
                content.append(f"  - {addr}\n", style="red")

        if diff_result.get("modified_bbmds"):
            content.append("\nModified BBMDs:\n", style="bold yellow")
            for mod in diff_result["modified_bbmds"]:
                content.append(f"\n  {mod['address']}:\n", style="cyan")
                for added in mod["added_links"]:
                    content.append(f"    + link to {added}\n", style="green")
                for removed in mod["removed_links"]:
                    content.append(f"    - link to {removed}\n", style="red")

        if not any(
            [diff_result.get("added_bbmds"), diff_result.get("removed_bbmds"), diff_result.get("modified_bbmds")]
        ):
            content.append("\nNo differences found.", style="dim")

        return Panel(
            content,
            title=f"[bold cyan]Diff: {snapshot_id} -> current[/bold cyan]",
            border_style="cyan",
        )

    @staticmethod
    def rewind_plan_panel(plan: List[dict], snapshot_id: str, description: str) -> Panel:
        """Create panel for rewind plan."""
        content = Text()

        for op in plan:
            content.append(f"\n{op['bbmd']}:\n", style="cyan bold")
            current = ", ".join(op["current_bdt"]) or "(empty)"
            target = ", ".join(op["target_bdt"]) or "(empty)"
            content.append("  Current BDT: ", style="dim")
            content.append(f"{current}\n")
            content.append("  Target BDT:  ", style="dim")
            content.append(f"{target}\n", style="bold")

        return Panel(
            content,
            title=f"[bold cyan]Rewind Plan to: {snapshot_id}[/bold cyan]",
            subtitle=f"[dim]{description}[/dim]",
            border_style="cyan",
        )
