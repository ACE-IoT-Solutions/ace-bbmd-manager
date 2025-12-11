"""Click CLI for BBMD Manager."""

import asyncio
import configparser
import json
import os
import sys
from typing import List, Optional

import click

from .audit import AuditLog, RewindManager, SnapshotManager
from .client import BBMDClient, BBMDClientError
from .models import BBMDNetwork, BDTEntry
from .network import NetworkManager, NetworkWalker


# Default file paths
DEFAULT_STATE_FILE = ".bbmd_state.json"
DEFAULT_AUDIT_FILE = ".bbmd_audit.json"
DEFAULT_SNAPSHOT_FILE = ".bbmd_snapshots.json"
DEFAULT_BACPYPES_INI = "BACpypes.ini"


def get_address_from_ini(ini_path: str = DEFAULT_BACPYPES_INI) -> Optional[str]:
    """Read local address from BACpypes.ini file if present.

    Args:
        ini_path: Path to the BACpypes.ini file (default: BACpypes.ini in CWD)

    Returns:
        The address string (without CIDR suffix) or None if not found
    """
    if not os.path.exists(ini_path):
        return None

    config = configparser.ConfigParser()
    try:
        config.read(ini_path)
        if 'BACpypes' in config and 'address' in config['BACpypes']:
            address = config['BACpypes']['address']
            # Strip CIDR suffix if present (e.g., "192.168.1.100/24" -> "192.168.1.100")
            if '/' in address:
                address = address.split('/')[0]
            return address
    except (configparser.Error, KeyError):
        pass

    return None


class Context:
    """CLI context object for sharing state."""

    def __init__(self):
        self.local_address: Optional[str] = None
        self.state_file: str = DEFAULT_STATE_FILE
        self.audit_log: Optional[AuditLog] = None
        self.snapshot_manager: Optional[SnapshotManager] = None
        self.network: Optional[BBMDNetwork] = None
        self.verbose: bool = False
        self.debug: bool = False

    def log(self, message: str, nl: bool = True):
        """Print message if verbose mode is on."""
        if self.verbose:
            click.echo(message, nl=nl)

    def load_state(self):
        """Load network state from file."""
        try:
            with open(self.state_file, 'r') as f:
                data = json.load(f)
                self.network = BBMDNetwork.from_dict(data)
        except FileNotFoundError:
            self.network = BBMDNetwork()
        except json.JSONDecodeError:
            self.network = BBMDNetwork()

    def save_state(self):
        """Save network state to file."""
        if self.network:
            with open(self.state_file, 'w') as f:
                json.dump(self.network.to_dict(), f, indent=2)


pass_context = click.make_pass_decorator(Context, ensure=True)


@click.group()
@click.option('--local-address', '-l', envvar='BBMD_LOCAL_ADDRESS',
              help='Local IP address for BACnet communication (also reads from BACpypes.ini)')
@click.option('--state-file', '-s', default=DEFAULT_STATE_FILE,
              help='Path to state file')
@click.option('--audit-file', '-a', default=DEFAULT_AUDIT_FILE,
              help='Path to audit log file')
@click.option('--snapshot-file', default=DEFAULT_SNAPSHOT_FILE,
              help='Path to snapshots file')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--debug', '-d', is_flag=True, help='Enable debug output for BACnet protocol')
@pass_context
def cli(ctx: Context, local_address: Optional[str], state_file: str,
        audit_file: str, snapshot_file: str, verbose: bool, debug: bool):
    """BBMD Manager - Manage BACnet BBMD Broadcast Distribution Tables.

    This tool allows you to read, modify, and manage BDTs across a network
    of BBMDs, with full audit logging and rollback capability.
    """
    # Check for BACpypes.ini if no local address provided
    if local_address is None:
        ini_address = get_address_from_ini()
        if ini_address:
            local_address = ini_address
            if verbose or debug:
                click.echo(f"Using address from BACpypes.ini: {local_address}")

    ctx.local_address = local_address
    ctx.state_file = state_file
    ctx.verbose = verbose or debug
    ctx.debug = debug
    ctx.audit_log = AuditLog(audit_file)
    ctx.snapshot_manager = SnapshotManager(snapshot_file)

    if debug:
        click.echo("Debug mode enabled")
    ctx.load_state()


# ============================================================================
# Network Discovery Commands
# ============================================================================

@cli.command()
@click.argument('addresses', nargs=-1, required=True)
@click.option('--depth', '-d', default=10, help='Maximum traversal depth')
@pass_context
def walk(ctx: Context, addresses: tuple, depth: int):
    """Walk the BBMD network starting from seed addresses.

    This discovers all BBMDs reachable from the given starting points
    by reading each BBMD's BDT and following the links.

    Examples:
        bbmd-manager walk 192.168.1.1
        bbmd-manager walk 192.168.1.1:47808 192.168.1.2:47808
    """
    if not ctx.local_address:
        raise click.ClickException("Local address required. Use --local-address or set BBMD_LOCAL_ADDRESS")

    async def do_walk():
        click.echo(f"Walking network from {len(addresses)} seed address(es)...")

        async with BBMDClient(ctx.local_address, debug=ctx.debug) as client:
            walker = NetworkWalker(client, progress_callback=click.echo if ctx.verbose else None)
            ctx.network = await walker.walk(list(addresses), max_depth=depth)

        ctx.save_state()

        # Log the walk
        ctx.audit_log.log(
            action="walk_network",
            bbmd_address="*",
            details={
                "seed_addresses": list(addresses),
                "discovered_count": len(ctx.network.bbmds),
                "depth": depth
            }
        )

        click.echo(f"\nDiscovered {len(ctx.network.bbmds)} BBMD(s):")
        for addr in sorted(ctx.network.bbmds.keys()):
            bbmd = ctx.network.bbmds[addr]
            click.echo(f"  {addr} - {len(bbmd.bdt)} BDT entries")

    asyncio.run(do_walk())


@cli.command()
@click.argument('address')
@pass_context
def read(ctx: Context, address: str):
    """Read the BDT from a single BBMD.

    Examples:
        bbmd-manager read 192.168.1.1
        bbmd-manager read 192.168.1.1:47808
    """
    if not ctx.local_address:
        raise click.ClickException("Local address required. Use --local-address or set BBMD_LOCAL_ADDRESS")

    async def do_read():
        async with BBMDClient(ctx.local_address, debug=ctx.debug) as client:
            try:
                bbmd = await client.read_bdt(address)
                ctx.network.bbmds[bbmd.address] = bbmd
                ctx.save_state()

                ctx.audit_log.log(
                    action="read_bdt",
                    bbmd_address=bbmd.address,
                    details={"entry_count": len(bbmd.bdt)}
                )

                click.echo(f"\nBDT for {bbmd.address}:")
                if bbmd.bdt:
                    for entry in bbmd.bdt:
                        click.echo(f"  {entry.address}")
                else:
                    click.echo("  (empty)")

            except BBMDClientError as e:
                raise click.ClickException(str(e))

    asyncio.run(do_read())


# ============================================================================
# Network Status Commands
# ============================================================================

@cli.command()
@click.option('--format', '-f', 'output_format', type=click.Choice(['text', 'json']),
              default='text', help='Output format')
@pass_context
def status(ctx: Context, output_format: str):
    """Show current network state.

    Displays all known BBMDs and their BDT entries from the cached state.
    """
    if not ctx.network.bbmds:
        click.echo("No network state. Run 'walk' or 'read' first.")
        return

    if output_format == 'json':
        click.echo(json.dumps(ctx.network.to_dict(), indent=2))
    else:
        click.echo(f"\nBBMD Network Status ({len(ctx.network.bbmds)} BBMDs)")
        click.echo("=" * 60)

        for addr in sorted(ctx.network.bbmds.keys()):
            bbmd = ctx.network.bbmds[addr]
            click.echo(f"\n{addr}")
            if bbmd.last_read:
                click.echo(f"  Last read: {bbmd.last_read.strftime('%Y-%m-%d %H:%M:%S')}")
            click.echo(f"  BDT entries ({len(bbmd.bdt)}):")
            for entry in bbmd.bdt:
                click.echo(f"    -> {entry.address}")


@cli.command()
@pass_context
def links(ctx: Context):
    """Show all links in the network as a list.

    Displays directed links between BBMDs with bidirectional indication.
    """
    if not ctx.network.bbmds:
        click.echo("No network state. Run 'walk' or 'read' first.")
        return

    all_links = ctx.network.get_links()

    if not all_links:
        click.echo("No links found in network.")
        return

    click.echo(f"\nNetwork Links ({len(all_links)} directed links)")
    click.echo("=" * 60)

    # Group by source
    shown_bidirectional = set()
    for source, target in sorted(all_links):
        pair = tuple(sorted([source, target]))
        is_bidirectional = ctx.network.has_bidirectional_link(source, target)

        if is_bidirectional:
            if pair not in shown_bidirectional:
                click.echo(f"  {source} <-> {target}  (bidirectional)")
                shown_bidirectional.add(pair)
        else:
            click.echo(f"  {source} --> {target}")


# ============================================================================
# Link Management Commands
# ============================================================================

@cli.command('add-link')
@click.argument('source')
@click.argument('target')
@click.option('--bidirectional', '-b', is_flag=True,
              help='Create bidirectional link (both directions)')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompt')
@pass_context
def add_link(ctx: Context, source: str, target: str, bidirectional: bool, yes: bool):
    """Add a link from source BBMD to target BBMD.

    Examples:
        bbmd-manager add-link 192.168.1.1 192.168.1.2
        bbmd-manager add-link 192.168.1.1 192.168.1.2 --bidirectional
    """
    if not ctx.local_address:
        raise click.ClickException("Local address required. Use --local-address or set BBMD_LOCAL_ADDRESS")

    # Normalize addresses
    if ":" not in source:
        source = f"{source}:47808"
    if ":" not in target:
        target = f"{target}:47808"

    async def do_add_link():
        # Use single client connection for both read and write operations
        async with BBMDClient(ctx.local_address, debug=ctx.debug) as client:
            click.echo("Reading current BDT state from devices...")

            try:
                # Read source BBMD
                click.echo(f"  Reading {source}...")
                source_bbmd = await client.read_bdt(source)
                ctx.network.bbmds[source] = source_bbmd

                # Read target BBMD if bidirectional
                if bidirectional:
                    click.echo(f"  Reading {target}...")
                    target_bbmd = await client.read_bdt(target)
                    ctx.network.bbmds[target] = target_bbmd

            except BBMDClientError as e:
                raise click.ClickException(f"Failed to read BDT: {e}")

            # Build the change plan
            changes = []

            # Check source BBMD
            source_bbmd = ctx.network.bbmds[source]
            current_entries = [e.address for e in source_bbmd.bdt]
            if target not in current_entries:
                new_entries = current_entries + [target]
                changes.append({
                    "bbmd": source,
                    "action": "add_entry",
                    "current_bdt": current_entries,
                    "new_bdt": new_entries,
                    "adding": target
                })
            else:
                click.echo(f"Note: {source} already has link to {target}")

            # Check target BBMD for bidirectional
            if bidirectional:
                target_bbmd = ctx.network.bbmds[target]
                current_entries = [e.address for e in target_bbmd.bdt]
                if source not in current_entries:
                    new_entries = current_entries + [source]
                    changes.append({
                        "bbmd": target,
                        "action": "add_entry",
                        "current_bdt": current_entries,
                        "new_bdt": new_entries,
                        "adding": source
                    })
                else:
                    click.echo(f"Note: {target} already has link to {source}")

            if not changes:
                click.echo("No changes needed - links already exist.")
                return

            # Display the change plan
            click.echo(f"\n{'=' * 60}")
            click.echo("PROPOSED CHANGES")
            click.echo(f"{'=' * 60}")

            for change in changes:
                click.echo(f"\nBBMD: {change['bbmd']}")
                click.echo(f"  Action: Add entry -> {change['adding']}")
                click.echo(f"  Current BDT: {', '.join(change['current_bdt']) or '(empty)'}")
                click.echo(f"  New BDT:     {', '.join(change['new_bdt'])}")

            click.echo(f"\n{'=' * 60}")
            click.echo(f"Total BBMDs to modify: {len(changes)}")
            click.echo(f"{'=' * 60}")

            if not yes:
                if not click.confirm("\nProceed with these changes?"):
                    click.echo("Aborted.")
                    return

            # Create snapshot before change
            rewind = RewindManager(ctx.audit_log, ctx.snapshot_manager)
            snapshot_id = rewind.prepare_change(
                ctx.network,
                f"add {'bidirectional ' if bidirectional else ''}link {source} -> {target}"
            )
            click.echo(f"\nCreated rollback snapshot: {snapshot_id}")

            manager = NetworkManager(client, ctx.network)
            try:
                click.echo("\nApplying changes...")
                modified = await manager.add_link(source, target, bidirectional=bidirectional)

                ctx.save_state()

                ctx.audit_log.log(
                    action="add_link",
                    bbmd_address=source,
                    details={
                        "target": target,
                        "bidirectional": bidirectional,
                        "modified_bbmds": modified
                    },
                    snapshot_id=snapshot_id
                )

                for addr in modified:
                    click.echo(f"  Updated {addr}")

                click.echo(f"\nSuccess! Modified {len(modified)} BBMD(s).")
                click.echo(f"To undo: bbmd-manager rewind {snapshot_id}")

            except BBMDClientError as e:
                raise click.ClickException(str(e))

    asyncio.run(do_add_link())


@cli.command('delete-link')
@click.argument('source')
@click.argument('target')
@click.option('--bidirectional', '-b', is_flag=True,
              help='Delete bidirectional link (both directions)')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompt')
@pass_context
def delete_link(ctx: Context, source: str, target: str, bidirectional: bool, yes: bool):
    """Delete a link from source BBMD to target BBMD.

    Examples:
        bbmd-manager delete-link 192.168.1.1 192.168.1.2
        bbmd-manager delete-link 192.168.1.1 192.168.1.2 --bidirectional
    """
    if not ctx.local_address:
        raise click.ClickException("Local address required. Use --local-address or set BBMD_LOCAL_ADDRESS")

    # Normalize addresses
    if ":" not in source:
        source = f"{source}:47808"
    if ":" not in target:
        target = f"{target}:47808"

    async def do_delete_link():
        # Use single client connection for both read and write operations
        async with BBMDClient(ctx.local_address, debug=ctx.debug) as client:
            click.echo("Reading current BDT state from devices...")

            try:
                # Read source BBMD
                click.echo(f"  Reading {source}...")
                source_bbmd = await client.read_bdt(source)
                ctx.network.bbmds[source] = source_bbmd

                # Read target BBMD if bidirectional
                if bidirectional:
                    click.echo(f"  Reading {target}...")
                    target_bbmd = await client.read_bdt(target)
                    ctx.network.bbmds[target] = target_bbmd

            except BBMDClientError as e:
                raise click.ClickException(f"Failed to read BDT: {e}")

            # Build the change plan
            changes = []

            # Check source BBMD
            source_bbmd = ctx.network.bbmds[source]
            current_entries = [e.address for e in source_bbmd.bdt]
            if target in current_entries:
                new_entries = [e for e in current_entries if e != target]
                changes.append({
                    "bbmd": source,
                    "action": "remove_entry",
                    "current_bdt": current_entries,
                    "new_bdt": new_entries,
                    "removing": target
                })
            else:
                click.echo(f"Note: {source} does not have link to {target}")

            # Check target BBMD for bidirectional
            if bidirectional:
                target_bbmd = ctx.network.bbmds[target]
                current_entries = [e.address for e in target_bbmd.bdt]
                if source in current_entries:
                    new_entries = [e for e in current_entries if e != source]
                    changes.append({
                        "bbmd": target,
                        "action": "remove_entry",
                        "current_bdt": current_entries,
                        "new_bdt": new_entries,
                        "removing": source
                    })
                else:
                    click.echo(f"Note: {target} does not have link to {source}")

            if not changes:
                click.echo("No changes needed - links do not exist.")
                return

            # Display the change plan
            click.echo(f"\n{'=' * 60}")
            click.echo("PROPOSED CHANGES")
            click.echo(f"{'=' * 60}")

            for change in changes:
                click.echo(f"\nBBMD: {change['bbmd']}")
                click.echo(f"  Action: Remove entry -> {change['removing']}")
                click.echo(f"  Current BDT: {', '.join(change['current_bdt'])}")
                click.echo(f"  New BDT:     {', '.join(change['new_bdt']) or '(empty)'}")

            click.echo(f"\n{'=' * 60}")
            click.echo(f"Total BBMDs to modify: {len(changes)}")
            click.echo(f"{'=' * 60}")

            if not yes:
                if not click.confirm("\nProceed with these changes?"):
                    click.echo("Aborted.")
                    return

            # Create snapshot before change
            rewind = RewindManager(ctx.audit_log, ctx.snapshot_manager)
            snapshot_id = rewind.prepare_change(
                ctx.network,
                f"delete {'bidirectional ' if bidirectional else ''}link {source} -> {target}"
            )
            click.echo(f"\nCreated rollback snapshot: {snapshot_id}")

            manager = NetworkManager(client, ctx.network)
            try:
                click.echo("\nApplying changes...")
                modified = await manager.delete_link(source, target, bidirectional=bidirectional)

                ctx.save_state()

                ctx.audit_log.log(
                    action="delete_link",
                    bbmd_address=source,
                    details={
                        "target": target,
                        "bidirectional": bidirectional,
                        "modified_bbmds": modified
                    },
                    snapshot_id=snapshot_id
                )

                for addr in modified:
                    click.echo(f"  Updated {addr}")

                click.echo(f"\nSuccess! Modified {len(modified)} BBMD(s).")
                click.echo(f"To undo: bbmd-manager rewind {snapshot_id}")

            except BBMDClientError as e:
                raise click.ClickException(str(e))

    asyncio.run(do_delete_link())


@cli.command('delete-bbmd')
@click.argument('address')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompt')
@pass_context
def delete_bbmd(ctx: Context, address: str, yes: bool):
    """Remove a BBMD from the network.

    This removes the BBMD from all other BBMDs' BDTs and clears its own BDT.

    Requires a prior 'walk' or 'read' to know which BBMDs to check.

    Examples:
        bbmd-manager delete-bbmd 192.168.1.3
    """
    if not ctx.local_address:
        raise click.ClickException("Local address required. Use --local-address or set BBMD_LOCAL_ADDRESS")

    # Normalize address
    if ":" not in address:
        address = f"{address}:47808"

    if not ctx.network.bbmds:
        raise click.ClickException("No cached network state. Run 'walk' first to discover BBMDs.")

    # Get list of BBMDs to read from cache (we need to know all BBMDs in the network)
    bbmds_to_read = list(ctx.network.bbmds.keys())
    if address not in bbmds_to_read:
        bbmds_to_read.append(address)

    async def do_delete_bbmd():
        # Use single client connection for both read and write operations
        async with BBMDClient(ctx.local_address, debug=ctx.debug) as client:
            click.echo("Reading current BDT state from devices...")

            # Read live BDT data from all known BBMDs
            for bbmd_addr in bbmds_to_read:
                try:
                    click.echo(f"  Reading {bbmd_addr}...")
                    bbmd = await client.read_bdt(bbmd_addr)
                    ctx.network.bbmds[bbmd_addr] = bbmd
                except BBMDClientError as e:
                    click.echo(f"  Warning: Failed to read {bbmd_addr}: {e}")

            if address not in ctx.network.bbmds:
                raise click.ClickException(f"Could not read BDT from {address}")

            # Build the change plan
            changes = []

            # Find all BBMDs that have this address in their BDT
            for bbmd_addr, bbmd in ctx.network.bbmds.items():
                if bbmd_addr == address:
                    continue
                current_entries = [e.address for e in bbmd.bdt]
                if address in current_entries:
                    new_entries = [e for e in current_entries if e != address]
                    changes.append({
                        "bbmd": bbmd_addr,
                        "action": "remove_entry",
                        "current_bdt": current_entries,
                        "new_bdt": new_entries,
                        "removing": address
                    })

            # Also clear the target BBMD's own BDT
            target_bbmd = ctx.network.bbmds[address]
            if target_bbmd.bdt:
                changes.append({
                    "bbmd": address,
                    "action": "clear_bdt",
                    "current_bdt": [e.address for e in target_bbmd.bdt],
                    "new_bdt": [],
                    "removing": "(all entries)"
                })

            if not changes:
                click.echo("No changes needed - BBMD has no links to/from other BBMDs.")
                return

            # Display the change plan
            click.echo(f"\n{'=' * 60}")
            click.echo(f"PROPOSED CHANGES - Remove BBMD {address}")
            click.echo(f"{'=' * 60}")

            for change in changes:
                click.echo(f"\nBBMD: {change['bbmd']}")
                if change['action'] == 'clear_bdt':
                    click.echo(f"  Action: Clear entire BDT")
                else:
                    click.echo(f"  Action: Remove entry -> {change['removing']}")
                click.echo(f"  Current BDT: {', '.join(change['current_bdt'])}")
                click.echo(f"  New BDT:     {', '.join(change['new_bdt']) or '(empty)'}")

            click.echo(f"\n{'=' * 60}")
            click.echo(f"Total BBMDs to modify: {len(changes)}")
            click.echo(f"{'=' * 60}")

            if not yes:
                if not click.confirm("\nProceed with these changes?"):
                    click.echo("Aborted.")
                    return

            # Create snapshot before change
            rewind = RewindManager(ctx.audit_log, ctx.snapshot_manager)
            snapshot_id = rewind.prepare_change(ctx.network, f"delete BBMD {address}")
            click.echo(f"\nCreated rollback snapshot: {snapshot_id}")

            manager = NetworkManager(client, ctx.network)
            try:
                click.echo("\nApplying changes...")
                modified = await manager.delete_bbmd(address)

                ctx.save_state()

                ctx.audit_log.log(
                    action="delete_bbmd",
                    bbmd_address=address,
                    details={"modified_bbmds": modified},
                    snapshot_id=snapshot_id
                )

                for addr in modified:
                    click.echo(f"  Updated {addr}")

                click.echo(f"\nSuccess! Modified {len(modified)} BBMD(s).")
                click.echo(f"To undo: bbmd-manager rewind {snapshot_id}")

            except BBMDClientError as e:
                raise click.ClickException(str(e))

    asyncio.run(do_delete_bbmd())


# ============================================================================
# Audit and Rewind Commands
# ============================================================================

@cli.command()
@click.option('--limit', '-n', default=20, help='Number of entries to show')
@click.option('--action', '-a', 'action_filter', help='Filter by action type')
@click.option('--bbmd', '-b', 'bbmd_filter', help='Filter by BBMD address')
@pass_context
def audit(ctx: Context, limit: int, action_filter: Optional[str], bbmd_filter: Optional[str]):
    """Show audit log entries.

    Examples:
        bbmd-manager audit
        bbmd-manager audit --limit 50
        bbmd-manager audit --action add_link
        bbmd-manager audit --bbmd 192.168.1.1:47808
    """
    entries = ctx.audit_log.get_entries(limit=limit, action_filter=action_filter, bbmd_filter=bbmd_filter)

    if not entries:
        click.echo("No audit log entries found.")
        return

    click.echo(f"\nAudit Log (showing {len(entries)} entries)")
    click.echo("=" * 80)

    for entry in entries:
        ts = entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        click.echo(f"\n[{ts}] {entry.action}")
        click.echo(f"  BBMD: {entry.bbmd_address}")
        for key, value in entry.details.items():
            click.echo(f"  {key}: {value}")
        if entry.snapshot_id:
            click.echo(f"  Snapshot: {entry.snapshot_id}")


@cli.command()
@click.option('--limit', '-n', default=10, help='Number of snapshots to show')
@pass_context
def snapshots(ctx: Context, limit: int):
    """List available snapshots for rollback.

    Examples:
        bbmd-manager snapshots
        bbmd-manager snapshots --limit 5
    """
    snapshot_list = ctx.snapshot_manager.list(limit=limit)

    if not snapshot_list:
        click.echo("No snapshots available.")
        return

    click.echo(f"\nAvailable Snapshots ({len(snapshot_list)} shown)")
    click.echo("=" * 80)

    for snapshot in snapshot_list:
        ts = snapshot.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        bbmd_count = len(snapshot.network_state.bbmds)
        click.echo(f"\n{snapshot.id}")
        click.echo(f"  Created: {ts}")
        click.echo(f"  Description: {snapshot.description}")
        click.echo(f"  BBMDs in snapshot: {bbmd_count}")


@cli.command()
@click.argument('snapshot_id')
@pass_context
def diff(ctx: Context, snapshot_id: str):
    """Show differences between a snapshot and current state.

    Examples:
        bbmd-manager diff 20240101_120000_abc12345
    """
    diff_result = ctx.snapshot_manager.get_diff(snapshot_id, ctx.network)

    if "error" in diff_result:
        raise click.ClickException(diff_result["error"])

    click.echo(f"\nDifference: {snapshot_id} -> current state")
    click.echo("=" * 60)

    if diff_result["added_bbmds"]:
        click.echo("\nAdded BBMDs:")
        for addr in diff_result["added_bbmds"]:
            click.echo(f"  + {addr}")

    if diff_result["removed_bbmds"]:
        click.echo("\nRemoved BBMDs:")
        for addr in diff_result["removed_bbmds"]:
            click.echo(f"  - {addr}")

    if diff_result["modified_bbmds"]:
        click.echo("\nModified BBMDs:")
        for mod in diff_result["modified_bbmds"]:
            click.echo(f"\n  {mod['address']}:")
            for added in mod["added_links"]:
                click.echo(f"    + link to {added}")
            for removed in mod["removed_links"]:
                click.echo(f"    - link to {removed}")

    if not any([diff_result["added_bbmds"], diff_result["removed_bbmds"], diff_result["modified_bbmds"]]):
        click.echo("\nNo differences found.")


@cli.command()
@click.argument('snapshot_id')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompt')
@click.option('--dry-run', is_flag=True, help='Show what would be done without making changes')
@pass_context
def rewind(ctx: Context, snapshot_id: str, yes: bool, dry_run: bool):
    """Rewind the network to a previous snapshot state.

    This will restore all BBMDs' BDTs to match the snapshot.

    Examples:
        bbmd-manager rewind 20240101_120000_abc12345
        bbmd-manager rewind 20240101_120000_abc12345 --dry-run
    """
    if not ctx.local_address and not dry_run:
        raise click.ClickException("Local address required. Use --local-address or set BBMD_LOCAL_ADDRESS")

    snapshot = ctx.snapshot_manager.get(snapshot_id)
    if not snapshot:
        raise click.ClickException(f"Snapshot not found: {snapshot_id}")

    rewind_mgr = RewindManager(ctx.audit_log, ctx.snapshot_manager)
    plan = rewind_mgr.get_rewind_plan(snapshot_id, ctx.network)

    if not plan:
        click.echo("No changes needed - current state matches snapshot.")
        return

    click.echo(f"\nRewind Plan to: {snapshot_id}")
    click.echo(f"Description: {snapshot.description}")
    click.echo("=" * 60)

    for op in plan:
        click.echo(f"\n{op['bbmd']}:")
        click.echo(f"  Current BDT: {', '.join(op['current_bdt']) or '(empty)'}")
        click.echo(f"  Target BDT:  {', '.join(op['target_bdt']) or '(empty)'}")

    if dry_run:
        click.echo("\n[DRY RUN] No changes made.")
        return

    if not yes:
        if not click.confirm("\nProceed with rewind?"):
            click.echo("Aborted.")
            return

    # Create snapshot of current state before rewind
    pre_rewind_snapshot = ctx.snapshot_manager.create(
        ctx.network,
        f"Before rewind to {snapshot_id}"
    )

    async def do_rewind():
        click.echo(f"\nCreated pre-rewind snapshot: {pre_rewind_snapshot}")
        click.echo("Applying rewind...")

        async with BBMDClient(ctx.local_address, debug=ctx.debug) as client:
            manager = NetworkManager(client, ctx.network)
            errors = []

            for op in plan:
                try:
                    entries = [BDTEntry(address=addr) for addr in op['target_bdt']]
                    await manager.set_bdt(op['bbmd'], entries)
                    click.echo(f"  Restored {op['bbmd']}")
                except BBMDClientError as e:
                    errors.append(f"{op['bbmd']}: {e}")
                    click.echo(f"  FAILED {op['bbmd']}: {e}")

        ctx.save_state()

        ctx.audit_log.log(
            action="rewind",
            bbmd_address="*",
            details={
                "target_snapshot": snapshot_id,
                "operations_count": len(plan),
                "errors": errors
            },
            snapshot_id=pre_rewind_snapshot
        )

        if errors:
            click.echo(f"\nRewind completed with {len(errors)} error(s).")
        else:
            click.echo("\nRewind completed successfully.")

    asyncio.run(do_rewind())


# ============================================================================
# Utility Commands
# ============================================================================

@cli.command()
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompt')
@pass_context
def clear_state(ctx: Context, yes: bool):
    """Clear all cached state (does not affect actual BBMDs)."""
    if not yes:
        if not click.confirm("Clear all cached state?"):
            click.echo("Aborted.")
            return

    ctx.network = BBMDNetwork()
    ctx.save_state()
    click.echo("State cleared.")


@cli.command()
@click.option('--all', '-a', 'clear_all', is_flag=True, help='Clear audit log and snapshots too')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompt')
@pass_context
def clear_history(ctx: Context, clear_all: bool, yes: bool):
    """Clear audit log and/or snapshots."""
    if clear_all:
        msg = "Clear audit log AND snapshots?"
    else:
        msg = "Clear audit log? (use --all to also clear snapshots)"

    if not yes:
        if not click.confirm(msg):
            click.echo("Aborted.")
            return

    ctx.audit_log.clear()
    click.echo("Audit log cleared.")

    if clear_all:
        ctx.snapshot_manager.clear()
        click.echo("Snapshots cleared.")


def main():
    """Entry point for the CLI."""
    cli()


if __name__ == '__main__':
    main()
