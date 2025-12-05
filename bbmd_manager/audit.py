"""Audit logging and snapshot management for BBMD Manager."""

import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .models import AuditEntry, BBMDNetwork, Snapshot, BBMD, BDTEntry


class AuditLog:
    """Manages audit logging with persistence."""

    def __init__(self, log_file: str = ".bbmd_audit.json"):
        """
        Initialize the audit log.

        Args:
            log_file: Path to the audit log file
        """
        self.log_file = Path(log_file)
        self.entries: List[AuditEntry] = []
        self._load()

    def _load(self):
        """Load audit log from file."""
        if self.log_file.exists():
            try:
                with open(self.log_file, 'r') as f:
                    data = json.load(f)
                    self.entries = [AuditEntry.from_dict(e) for e in data.get("entries", [])]
            except (json.JSONDecodeError, KeyError):
                self.entries = []

    def _save(self):
        """Save audit log to file."""
        data = {"entries": [e.to_dict() for e in self.entries]}
        with open(self.log_file, 'w') as f:
            json.dump(data, f, indent=2)

    def log(self, action: str, bbmd_address: str, details: dict, snapshot_id: Optional[str] = None):
        """
        Add an entry to the audit log.

        Args:
            action: The action being logged
            bbmd_address: The BBMD address involved
            details: Additional details about the action
            snapshot_id: Optional snapshot ID for rollback reference
        """
        entry = AuditEntry(
            timestamp=datetime.now(),
            action=action,
            bbmd_address=bbmd_address,
            details=details,
            snapshot_id=snapshot_id
        )
        self.entries.append(entry)
        self._save()

    def get_entries(self, limit: Optional[int] = None, action_filter: Optional[str] = None,
                    bbmd_filter: Optional[str] = None) -> List[AuditEntry]:
        """
        Get audit log entries with optional filtering.

        Args:
            limit: Maximum number of entries to return
            action_filter: Filter by action type
            bbmd_filter: Filter by BBMD address

        Returns:
            List of matching audit entries (most recent first)
        """
        entries = list(reversed(self.entries))

        if action_filter:
            entries = [e for e in entries if e.action == action_filter]

        if bbmd_filter:
            entries = [e for e in entries if e.bbmd_address == bbmd_filter]

        if limit:
            entries = entries[:limit]

        return entries

    def clear(self):
        """Clear all audit log entries."""
        self.entries = []
        self._save()


class SnapshotManager:
    """Manages network state snapshots for rollback capability."""

    def __init__(self, snapshot_file: str = ".bbmd_snapshots.json"):
        """
        Initialize the snapshot manager.

        Args:
            snapshot_file: Path to the snapshots file
        """
        self.snapshot_file = Path(snapshot_file)
        self.snapshots: Dict[str, Snapshot] = {}
        self._load()

    def _load(self):
        """Load snapshots from file."""
        if self.snapshot_file.exists():
            try:
                with open(self.snapshot_file, 'r') as f:
                    data = json.load(f)
                    self.snapshots = {
                        sid: Snapshot.from_dict(s)
                        for sid, s in data.get("snapshots", {}).items()
                    }
            except (json.JSONDecodeError, KeyError):
                self.snapshots = {}

    def _save(self):
        """Save snapshots to file."""
        data = {"snapshots": {sid: s.to_dict() for sid, s in self.snapshots.items()}}
        with open(self.snapshot_file, 'w') as f:
            json.dump(data, f, indent=2)

    def create(self, network: BBMDNetwork, description: str = "") -> str:
        """
        Create a snapshot of the current network state.

        Args:
            network: Current network state
            description: Optional description for the snapshot

        Returns:
            Snapshot ID
        """
        snapshot_id = datetime.now().strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:8]

        # Deep copy the network state
        network_copy = BBMDNetwork.from_dict(network.to_dict())

        snapshot = Snapshot(
            id=snapshot_id,
            timestamp=datetime.now(),
            description=description,
            network_state=network_copy
        )

        self.snapshots[snapshot_id] = snapshot
        self._save()

        return snapshot_id

    def get(self, snapshot_id: str) -> Optional[Snapshot]:
        """
        Get a snapshot by ID.

        Args:
            snapshot_id: Snapshot ID

        Returns:
            Snapshot if found, None otherwise
        """
        return self.snapshots.get(snapshot_id)

    def list(self, limit: Optional[int] = None) -> List[Snapshot]:
        """
        List all snapshots.

        Args:
            limit: Maximum number of snapshots to return

        Returns:
            List of snapshots (most recent first)
        """
        snapshots = sorted(self.snapshots.values(), key=lambda s: s.timestamp, reverse=True)
        if limit:
            snapshots = snapshots[:limit]
        return snapshots

    def delete(self, snapshot_id: str) -> bool:
        """
        Delete a snapshot.

        Args:
            snapshot_id: Snapshot ID

        Returns:
            True if deleted, False if not found
        """
        if snapshot_id in self.snapshots:
            del self.snapshots[snapshot_id]
            self._save()
            return True
        return False

    def get_diff(self, snapshot_id: str, current_network: BBMDNetwork) -> Dict:
        """
        Get the difference between a snapshot and current state.

        Args:
            snapshot_id: Snapshot ID to compare
            current_network: Current network state

        Returns:
            Dictionary describing the differences
        """
        snapshot = self.get(snapshot_id)
        if not snapshot:
            return {"error": "Snapshot not found"}

        diff = {
            "added_bbmds": [],
            "removed_bbmds": [],
            "modified_bbmds": []
        }

        old_addrs = set(snapshot.network_state.bbmds.keys())
        new_addrs = set(current_network.bbmds.keys())

        diff["added_bbmds"] = list(new_addrs - old_addrs)
        diff["removed_bbmds"] = list(old_addrs - new_addrs)

        # Check for modifications
        for addr in old_addrs & new_addrs:
            old_bdt = {e.address for e in snapshot.network_state.bbmds[addr].bdt}
            new_bdt = {e.address for e in current_network.bbmds[addr].bdt}

            if old_bdt != new_bdt:
                diff["modified_bbmds"].append({
                    "address": addr,
                    "added_links": list(new_bdt - old_bdt),
                    "removed_links": list(old_bdt - new_bdt)
                })

        return diff

    def clear(self):
        """Clear all snapshots."""
        self.snapshots = {}
        self._save()


class RewindManager:
    """Manages the ability to rewind changes using snapshots."""

    def __init__(self, audit_log: AuditLog, snapshot_manager: SnapshotManager):
        """
        Initialize the rewind manager.

        Args:
            audit_log: AuditLog instance
            snapshot_manager: SnapshotManager instance
        """
        self.audit_log = audit_log
        self.snapshot_manager = snapshot_manager

    def prepare_change(self, network: BBMDNetwork, description: str) -> str:
        """
        Prepare for a change by creating a snapshot.

        Args:
            network: Current network state
            description: Description of the upcoming change

        Returns:
            Snapshot ID for rollback reference
        """
        return self.snapshot_manager.create(network, f"Before: {description}")

    def get_rewind_plan(self, snapshot_id: str, current_network: BBMDNetwork) -> List[Dict]:
        """
        Get a plan for rewinding to a snapshot.

        Args:
            snapshot_id: Snapshot ID to rewind to
            current_network: Current network state

        Returns:
            List of operations needed to rewind
        """
        snapshot = self.snapshot_manager.get(snapshot_id)
        if not snapshot:
            return []

        operations = []
        target_state = snapshot.network_state

        # For each BBMD in the target state, we need to restore its BDT
        for addr, target_bbmd in target_state.bbmds.items():
            if addr in current_network.bbmds:
                current_bbmd = current_network.bbmds[addr]
                if set(e.address for e in current_bbmd.bdt) != set(e.address for e in target_bbmd.bdt):
                    operations.append({
                        "action": "write_bdt",
                        "bbmd": addr,
                        "current_bdt": [e.address for e in current_bbmd.bdt],
                        "target_bdt": [e.address for e in target_bbmd.bdt]
                    })

        return operations
