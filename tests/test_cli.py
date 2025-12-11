"""Tests for the CLI interface."""

import json
import os
import pytest
import tempfile
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from bbmd_manager.cli import cli
from bbmd_manager.models import BBMDNetwork, BBMD, BDTEntry


@pytest.fixture
def runner():
    """Create a CLI runner."""
    return CliRunner()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def state_file(temp_dir):
    """Create a temporary state file path."""
    return os.path.join(temp_dir, "state.json")


@pytest.fixture
def audit_file(temp_dir):
    """Create a temporary audit file path."""
    return os.path.join(temp_dir, "audit.json")


@pytest.fixture
def snapshot_file(temp_dir):
    """Create a temporary snapshot file path."""
    return os.path.join(temp_dir, "snapshots.json")


@pytest.fixture
def populated_state(state_file):
    """Create a state file with some test data."""
    network = BBMDNetwork()
    network.bbmds["192.168.1.1:47808"] = BBMD(
        address="192.168.1.1:47808",
        bdt=[
            BDTEntry(address="192.168.1.2:47808"),
            BDTEntry(address="192.168.1.3:47808"),
        ]
    )
    network.bbmds["192.168.1.2:47808"] = BBMD(
        address="192.168.1.2:47808",
        bdt=[
            BDTEntry(address="192.168.1.1:47808"),
        ]
    )
    network.bbmds["192.168.1.3:47808"] = BBMD(
        address="192.168.1.3:47808",
        bdt=[]
    )

    with open(state_file, 'w') as f:
        json.dump(network.to_dict(), f)

    return state_file


class TestStatusCommand:
    def test_status_empty(self, runner, state_file, audit_file, snapshot_file):
        result = runner.invoke(cli, [
            '--state-file', state_file,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'status'
        ])

        assert result.exit_code == 0
        assert "No network state" in result.output

    def test_status_with_data(self, runner, populated_state, audit_file, snapshot_file):
        result = runner.invoke(cli, [
            '--state-file', populated_state,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'status'
        ])

        assert result.exit_code == 0
        assert "192.168.1.1:47808" in result.output
        assert "192.168.1.2:47808" in result.output
        assert "3 BBMDs" in result.output

    def test_status_json_format(self, runner, populated_state, audit_file, snapshot_file):
        result = runner.invoke(cli, [
            '--state-file', populated_state,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'status', '--format', 'json'
        ])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "bbmds" in data
        assert "192.168.1.1:47808" in data["bbmds"]


class TestLinksCommand:
    def test_links_empty(self, runner, state_file, audit_file, snapshot_file):
        result = runner.invoke(cli, [
            '--state-file', state_file,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'links'
        ])

        assert result.exit_code == 0
        assert "No network state" in result.output

    def test_links_with_data(self, runner, populated_state, audit_file, snapshot_file):
        result = runner.invoke(cli, [
            '--state-file', populated_state,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'links'
        ])

        assert result.exit_code == 0
        # Should show bidirectional link between 1.1 and 1.2
        assert "bidirectional" in result.output.lower()
        # Should show unidirectional link from 1.1 to 1.3
        assert "-->" in result.output


class TestAuditCommand:
    def test_audit_empty(self, runner, state_file, audit_file, snapshot_file):
        result = runner.invoke(cli, [
            '--state-file', state_file,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'audit'
        ])

        assert result.exit_code == 0
        assert "No audit log entries" in result.output

    def test_audit_with_entries(self, runner, state_file, audit_file, snapshot_file):
        from bbmd_manager.audit import AuditLog

        # Create some audit entries
        log = AuditLog(audit_file)
        log.log(action="test_action", bbmd_address="A", details={"key": "value"})

        result = runner.invoke(cli, [
            '--state-file', state_file,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'audit'
        ])

        assert result.exit_code == 0
        assert "test_action" in result.output


class TestSnapshotsCommand:
    def test_snapshots_empty(self, runner, state_file, audit_file, snapshot_file):
        result = runner.invoke(cli, [
            '--state-file', state_file,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'snapshots'
        ])

        assert result.exit_code == 0
        assert "No snapshots" in result.output

    def test_snapshots_with_data(self, runner, state_file, audit_file, snapshot_file):
        from bbmd_manager.audit import SnapshotManager
        from bbmd_manager.models import BBMDNetwork

        # Create a snapshot
        manager = SnapshotManager(snapshot_file)
        manager.create(BBMDNetwork(), "Test snapshot")

        result = runner.invoke(cli, [
            '--state-file', state_file,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'snapshots'
        ])

        assert result.exit_code == 0
        assert "Test snapshot" in result.output


class TestDiffCommand:
    def test_diff_not_found(self, runner, state_file, audit_file, snapshot_file):
        result = runner.invoke(cli, [
            '--state-file', state_file,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'diff', 'nonexistent_id'
        ])

        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_diff_no_changes(self, runner, populated_state, audit_file, snapshot_file):
        from bbmd_manager.audit import SnapshotManager
        from bbmd_manager.models import BBMDNetwork

        # Load state and create snapshot
        with open(populated_state) as f:
            data = json.load(f)
        network = BBMDNetwork.from_dict(data)

        manager = SnapshotManager(snapshot_file)
        snapshot_id = manager.create(network, "Original")

        result = runner.invoke(cli, [
            '--state-file', populated_state,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'diff', snapshot_id
        ])

        assert result.exit_code == 0
        assert "No differences" in result.output


class TestClearCommands:
    def test_clear_state(self, runner, populated_state, audit_file, snapshot_file):
        result = runner.invoke(cli, [
            '--state-file', populated_state,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'clear-state', '--yes'
        ])

        assert result.exit_code == 0
        assert "cleared" in result.output.lower()

        # Verify state is empty
        with open(populated_state) as f:
            data = json.load(f)
        assert data["bbmds"] == {}

    def test_clear_history(self, runner, state_file, audit_file, snapshot_file):
        from bbmd_manager.audit import AuditLog

        # Create some audit entries
        log = AuditLog(audit_file)
        log.log(action="test", bbmd_address="A", details={})

        result = runner.invoke(cli, [
            '--state-file', state_file,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'clear-history', '--yes'
        ])

        assert result.exit_code == 0
        assert "cleared" in result.output.lower()


class TestReadCommand:
    def test_read_requires_local_address(self, runner, state_file, audit_file, snapshot_file):
        result = runner.invoke(cli, [
            '--state-file', state_file,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'read', '192.168.1.1'
        ])

        assert result.exit_code != 0
        assert "local address required" in result.output.lower()


class TestWalkCommand:
    def test_walk_requires_local_address(self, runner, state_file, audit_file, snapshot_file):
        result = runner.invoke(cli, [
            '--state-file', state_file,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'walk', '192.168.1.1'
        ])

        assert result.exit_code != 0
        assert "local address required" in result.output.lower()


class TestAddLinkCommand:
    def test_add_link_requires_local_address(self, runner, state_file, audit_file, snapshot_file):
        result = runner.invoke(cli, [
            '--state-file', state_file,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'add-link', '192.168.1.1', '192.168.1.2', '--yes'
        ])

        assert result.exit_code != 0
        assert "local address required" in result.output.lower()


class TestDeleteLinkCommand:
    def test_delete_link_requires_local_address(self, runner, state_file, audit_file, snapshot_file):
        result = runner.invoke(cli, [
            '--state-file', state_file,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'delete-link', '192.168.1.1', '192.168.1.2', '--yes'
        ])

        assert result.exit_code != 0
        assert "local address required" in result.output.lower()


class TestRewindCommand:
    def test_rewind_requires_local_address(self, runner, state_file, audit_file, snapshot_file):
        from bbmd_manager.audit import SnapshotManager
        from bbmd_manager.models import BBMDNetwork

        manager = SnapshotManager(snapshot_file)
        snapshot_id = manager.create(BBMDNetwork(), "Test")

        result = runner.invoke(cli, [
            '--state-file', state_file,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'rewind', snapshot_id, '--yes'
        ])

        assert result.exit_code != 0
        assert "local address required" in result.output.lower()

    def test_rewind_dry_run(self, runner, populated_state, audit_file, snapshot_file):
        from bbmd_manager.audit import SnapshotManager
        from bbmd_manager.models import BBMDNetwork

        # Load state
        with open(populated_state) as f:
            data = json.load(f)
        network = BBMDNetwork.from_dict(data)

        # Create snapshot
        manager = SnapshotManager(snapshot_file)
        snapshot_id = manager.create(network, "Before")

        # Modify state (remove a link)
        network.bbmds["192.168.1.1:47808"].bdt = []
        with open(populated_state, 'w') as f:
            json.dump(network.to_dict(), f)

        result = runner.invoke(cli, [
            '--state-file', populated_state,
            '--audit-file', audit_file,
            '--snapshot-file', snapshot_file,
            'rewind', snapshot_id, '--dry-run'
        ])

        assert result.exit_code == 0
        assert "DRY RUN" in result.output
        assert "192.168.1.1:47808" in result.output


class TestBACpypesIniIntegration:
    def test_get_address_from_ini_not_found(self, temp_dir):
        from bbmd_manager.cli import get_address_from_ini

        result = get_address_from_ini(os.path.join(temp_dir, "BACpypes.ini"))
        assert result is None

    def test_get_address_from_ini_basic(self, temp_dir):
        from bbmd_manager.cli import get_address_from_ini

        ini_path = os.path.join(temp_dir, "BACpypes.ini")
        with open(ini_path, 'w') as f:
            f.write("[BACpypes]\n")
            f.write("address: 192.168.1.100\n")

        result = get_address_from_ini(ini_path)
        assert result == "192.168.1.100"

    def test_get_address_from_ini_with_cidr(self, temp_dir):
        from bbmd_manager.cli import get_address_from_ini

        ini_path = os.path.join(temp_dir, "BACpypes.ini")
        with open(ini_path, 'w') as f:
            f.write("[BACpypes]\n")
            f.write("address: 192.168.1.100/24\n")

        result = get_address_from_ini(ini_path)
        assert result == "192.168.1.100"

    def test_get_address_from_ini_missing_section(self, temp_dir):
        from bbmd_manager.cli import get_address_from_ini

        ini_path = os.path.join(temp_dir, "BACpypes.ini")
        with open(ini_path, 'w') as f:
            f.write("[OtherSection]\n")
            f.write("address: 192.168.1.100\n")

        result = get_address_from_ini(ini_path)
        assert result is None

    def test_get_address_from_ini_missing_key(self, temp_dir):
        from bbmd_manager.cli import get_address_from_ini

        ini_path = os.path.join(temp_dir, "BACpypes.ini")
        with open(ini_path, 'w') as f:
            f.write("[BACpypes]\n")
            f.write("objectName: TestDevice\n")

        result = get_address_from_ini(ini_path)
        assert result is None

    def test_cli_uses_ini_address(self, runner, temp_dir):
        """Test that CLI uses address from BACpypes.ini when no other address is provided."""
        state_file = os.path.join(temp_dir, "state.json")
        audit_file = os.path.join(temp_dir, "audit.json")
        snapshot_file = os.path.join(temp_dir, "snapshots.json")
        ini_path = os.path.join(temp_dir, "BACpypes.ini")

        with open(ini_path, 'w') as f:
            f.write("[BACpypes]\n")
            f.write("address: 10.0.0.50/24\n")

        # Run with verbose to see the "Using address from BACpypes.ini" message
        # Use isolated filesystem to ensure we're in temp_dir
        with runner.isolated_filesystem(temp_dir=temp_dir) as td:
            # Create the INI file in the isolated filesystem
            with open("BACpypes.ini", 'w') as f:
                f.write("[BACpypes]\n")
                f.write("address: 10.0.0.50/24\n")

            result = runner.invoke(cli, [
                '--state-file', state_file,
                '--audit-file', audit_file,
                '--snapshot-file', snapshot_file,
                '--verbose',
                'status'
            ])

            assert result.exit_code == 0
            assert "Using address from BACpypes.ini: 10.0.0.50" in result.output
