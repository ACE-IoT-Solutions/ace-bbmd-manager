"""Tests for audit logging and snapshot management."""

import json
import os
import pytest
import tempfile
from datetime import datetime

from bbmd_manager.audit import AuditLog, SnapshotManager, RewindManager
from bbmd_manager.models import BBMDNetwork, BBMD, BDTEntry


@pytest.fixture
def temp_audit_file():
    """Create a temporary audit file."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def temp_snapshot_file():
    """Create a temporary snapshot file."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.unlink(path)


class TestAuditLog:
    def test_log_entry(self, temp_audit_file):
        log = AuditLog(temp_audit_file)

        log.log(
            action="test_action",
            bbmd_address="192.168.1.1:47808",
            details={"key": "value"}
        )

        assert len(log.entries) == 1
        assert log.entries[0].action == "test_action"

    def test_persistence(self, temp_audit_file):
        # Create and log
        log1 = AuditLog(temp_audit_file)
        log1.log(action="action1", bbmd_address="A", details={})
        log1.log(action="action2", bbmd_address="B", details={})

        # Reload
        log2 = AuditLog(temp_audit_file)
        assert len(log2.entries) == 2
        assert log2.entries[0].action == "action1"
        assert log2.entries[1].action == "action2"

    def test_get_entries_limit(self, temp_audit_file):
        log = AuditLog(temp_audit_file)

        for i in range(10):
            log.log(action=f"action{i}", bbmd_address="A", details={})

        entries = log.get_entries(limit=5)
        assert len(entries) == 5
        # Most recent first
        assert entries[0].action == "action9"

    def test_get_entries_filter_action(self, temp_audit_file):
        log = AuditLog(temp_audit_file)

        log.log(action="add_link", bbmd_address="A", details={})
        log.log(action="delete_link", bbmd_address="A", details={})
        log.log(action="add_link", bbmd_address="B", details={})

        entries = log.get_entries(action_filter="add_link")
        assert len(entries) == 2
        assert all(e.action == "add_link" for e in entries)

    def test_get_entries_filter_bbmd(self, temp_audit_file):
        log = AuditLog(temp_audit_file)

        log.log(action="action1", bbmd_address="A", details={})
        log.log(action="action2", bbmd_address="B", details={})
        log.log(action="action3", bbmd_address="A", details={})

        entries = log.get_entries(bbmd_filter="A")
        assert len(entries) == 2
        assert all(e.bbmd_address == "A" for e in entries)

    def test_clear(self, temp_audit_file):
        log = AuditLog(temp_audit_file)

        log.log(action="test", bbmd_address="A", details={})
        assert len(log.entries) == 1

        log.clear()
        assert len(log.entries) == 0

        # Verify persistence
        log2 = AuditLog(temp_audit_file)
        assert len(log2.entries) == 0


class TestSnapshotManager:
    def test_create_snapshot(self, temp_snapshot_file):
        manager = SnapshotManager(temp_snapshot_file)

        network = BBMDNetwork()
        network.bbmds["A"] = BBMD(address="A", bdt=[BDTEntry(address="B")])

        snapshot_id = manager.create(network, "Test snapshot")

        assert snapshot_id is not None
        assert snapshot_id in manager.snapshots

    def test_get_snapshot(self, temp_snapshot_file):
        manager = SnapshotManager(temp_snapshot_file)

        network = BBMDNetwork()
        network.bbmds["A"] = BBMD(address="A", bdt=[])

        snapshot_id = manager.create(network, "Test")

        snapshot = manager.get(snapshot_id)
        assert snapshot is not None
        assert snapshot.description == "Test"
        assert "A" in snapshot.network_state.bbmds

    def test_list_snapshots(self, temp_snapshot_file):
        manager = SnapshotManager(temp_snapshot_file)

        network = BBMDNetwork()
        manager.create(network, "First")
        manager.create(network, "Second")
        manager.create(network, "Third")

        snapshots = manager.list()
        assert len(snapshots) == 3
        # Most recent first
        assert snapshots[0].description == "Third"

    def test_list_with_limit(self, temp_snapshot_file):
        manager = SnapshotManager(temp_snapshot_file)

        network = BBMDNetwork()
        for i in range(5):
            manager.create(network, f"Snapshot {i}")

        snapshots = manager.list(limit=2)
        assert len(snapshots) == 2

    def test_delete_snapshot(self, temp_snapshot_file):
        manager = SnapshotManager(temp_snapshot_file)

        network = BBMDNetwork()
        snapshot_id = manager.create(network, "To delete")

        assert manager.delete(snapshot_id)
        assert manager.get(snapshot_id) is None

    def test_persistence(self, temp_snapshot_file):
        network = BBMDNetwork()
        network.bbmds["A"] = BBMD(address="A", bdt=[BDTEntry(address="B")])

        # Create and save
        manager1 = SnapshotManager(temp_snapshot_file)
        snapshot_id = manager1.create(network, "Persistent")

        # Reload
        manager2 = SnapshotManager(temp_snapshot_file)
        snapshot = manager2.get(snapshot_id)

        assert snapshot is not None
        assert snapshot.description == "Persistent"
        assert "A" in snapshot.network_state.bbmds

    def test_get_diff_no_changes(self, temp_snapshot_file):
        manager = SnapshotManager(temp_snapshot_file)

        network = BBMDNetwork()
        network.bbmds["A"] = BBMD(address="A", bdt=[BDTEntry(address="B")])

        snapshot_id = manager.create(network, "Original")

        diff = manager.get_diff(snapshot_id, network)

        assert diff["added_bbmds"] == []
        assert diff["removed_bbmds"] == []
        assert diff["modified_bbmds"] == []

    def test_get_diff_added_bbmd(self, temp_snapshot_file):
        manager = SnapshotManager(temp_snapshot_file)

        network = BBMDNetwork()
        network.bbmds["A"] = BBMD(address="A", bdt=[])

        snapshot_id = manager.create(network, "Original")

        # Add a BBMD
        network.bbmds["B"] = BBMD(address="B", bdt=[])

        diff = manager.get_diff(snapshot_id, network)

        assert "B" in diff["added_bbmds"]

    def test_get_diff_removed_bbmd(self, temp_snapshot_file):
        manager = SnapshotManager(temp_snapshot_file)

        network = BBMDNetwork()
        network.bbmds["A"] = BBMD(address="A", bdt=[])
        network.bbmds["B"] = BBMD(address="B", bdt=[])

        snapshot_id = manager.create(network, "Original")

        # Remove a BBMD
        del network.bbmds["B"]

        diff = manager.get_diff(snapshot_id, network)

        assert "B" in diff["removed_bbmds"]

    def test_get_diff_modified_bdt(self, temp_snapshot_file):
        manager = SnapshotManager(temp_snapshot_file)

        network = BBMDNetwork()
        network.bbmds["A"] = BBMD(address="A", bdt=[BDTEntry(address="B")])

        snapshot_id = manager.create(network, "Original")

        # Modify BDT
        network.bbmds["A"].bdt = [BDTEntry(address="C")]

        diff = manager.get_diff(snapshot_id, network)

        assert len(diff["modified_bbmds"]) == 1
        mod = diff["modified_bbmds"][0]
        assert mod["address"] == "A"
        assert "C" in mod["added_links"]
        assert "B" in mod["removed_links"]


class TestRewindManager:
    def test_prepare_change(self, temp_audit_file, temp_snapshot_file):
        audit_log = AuditLog(temp_audit_file)
        snapshot_manager = SnapshotManager(temp_snapshot_file)
        rewind = RewindManager(audit_log, snapshot_manager)

        network = BBMDNetwork()
        network.bbmds["A"] = BBMD(address="A", bdt=[])

        snapshot_id = rewind.prepare_change(network, "Test change")

        assert snapshot_id is not None
        snapshot = snapshot_manager.get(snapshot_id)
        assert "Before: Test change" in snapshot.description

    def test_get_rewind_plan_no_changes(self, temp_audit_file, temp_snapshot_file):
        audit_log = AuditLog(temp_audit_file)
        snapshot_manager = SnapshotManager(temp_snapshot_file)
        rewind = RewindManager(audit_log, snapshot_manager)

        network = BBMDNetwork()
        network.bbmds["A"] = BBMD(address="A", bdt=[BDTEntry(address="B")])

        snapshot_id = rewind.prepare_change(network, "No change")

        plan = rewind.get_rewind_plan(snapshot_id, network)
        assert plan == []

    def test_get_rewind_plan_with_changes(self, temp_audit_file, temp_snapshot_file):
        audit_log = AuditLog(temp_audit_file)
        snapshot_manager = SnapshotManager(temp_snapshot_file)
        rewind = RewindManager(audit_log, snapshot_manager)

        network = BBMDNetwork()
        network.bbmds["A"] = BBMD(address="A", bdt=[BDTEntry(address="B")])

        snapshot_id = rewind.prepare_change(network, "Before modification")

        # Modify
        network.bbmds["A"].bdt = [BDTEntry(address="C")]

        plan = rewind.get_rewind_plan(snapshot_id, network)

        assert len(plan) == 1
        assert plan[0]["action"] == "write_bdt"
        assert plan[0]["bbmd"] == "A"
        assert plan[0]["current_bdt"] == ["C"]
        assert plan[0]["target_bdt"] == ["B"]
