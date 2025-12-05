"""Tests for data models."""

import pytest
from datetime import datetime

from bbmd_manager.models import BDTEntry, BBMD, BBMDNetwork, AuditEntry, Snapshot


class TestBDTEntry:
    def test_creation(self):
        entry = BDTEntry(address="192.168.1.1:47808")
        assert entry.address == "192.168.1.1:47808"
        assert entry.mask == "255.255.255.255"

    def test_with_mask(self):
        entry = BDTEntry(address="192.168.1.1:47808", mask="255.255.255.0")
        assert entry.mask == "255.255.255.0"

    def test_equality(self):
        e1 = BDTEntry(address="192.168.1.1:47808")
        e2 = BDTEntry(address="192.168.1.1:47808")
        e3 = BDTEntry(address="192.168.1.2:47808")

        assert e1 == e2
        assert e1 != e3

    def test_hash(self):
        e1 = BDTEntry(address="192.168.1.1:47808")
        e2 = BDTEntry(address="192.168.1.1:47808")

        # Should be usable in sets
        s = {e1, e2}
        assert len(s) == 1

    def test_to_dict(self):
        entry = BDTEntry(address="192.168.1.1:47808", mask="255.255.255.0")
        d = entry.to_dict()

        assert d["address"] == "192.168.1.1:47808"
        assert d["mask"] == "255.255.255.0"

    def test_from_dict(self):
        d = {"address": "192.168.1.1:47808", "mask": "255.255.255.0"}
        entry = BDTEntry.from_dict(d)

        assert entry.address == "192.168.1.1:47808"
        assert entry.mask == "255.255.255.0"


class TestBBMD:
    def test_creation(self):
        bbmd = BBMD(address="192.168.1.1:47808")
        assert bbmd.address == "192.168.1.1:47808"
        assert bbmd.bdt == []
        assert bbmd.last_read is None

    def test_with_bdt(self):
        entries = [
            BDTEntry(address="192.168.1.2:47808"),
            BDTEntry(address="192.168.1.3:47808"),
        ]
        bbmd = BBMD(address="192.168.1.1:47808", bdt=entries)

        assert len(bbmd.bdt) == 2

    def test_get_peer_addresses(self):
        entries = [
            BDTEntry(address="192.168.1.1:47808"),  # Self
            BDTEntry(address="192.168.1.2:47808"),
            BDTEntry(address="192.168.1.3:47808"),
        ]
        bbmd = BBMD(address="192.168.1.1:47808", bdt=entries)

        peers = bbmd.get_peer_addresses()
        assert "192.168.1.2:47808" in peers
        assert "192.168.1.3:47808" in peers
        assert "192.168.1.1:47808" not in peers

    def test_to_dict_from_dict(self):
        entries = [BDTEntry(address="192.168.1.2:47808")]
        now = datetime.now()
        bbmd = BBMD(address="192.168.1.1:47808", bdt=entries, last_read=now)

        d = bbmd.to_dict()
        restored = BBMD.from_dict(d)

        assert restored.address == bbmd.address
        assert len(restored.bdt) == len(bbmd.bdt)
        assert restored.bdt[0].address == bbmd.bdt[0].address


class TestBBMDNetwork:
    def test_creation(self):
        network = BBMDNetwork()
        assert network.bbmds == {}

    def test_get_links(self):
        network = BBMDNetwork()

        # BBMD A -> B, C
        network.bbmds["A"] = BBMD(
            address="A",
            bdt=[BDTEntry(address="B"), BDTEntry(address="C")]
        )
        # BBMD B -> A
        network.bbmds["B"] = BBMD(
            address="B",
            bdt=[BDTEntry(address="A")]
        )

        links = network.get_links()
        assert ("A", "B") in links
        assert ("A", "C") in links
        assert ("B", "A") in links

    def test_has_bidirectional_link(self):
        network = BBMDNetwork()

        # A <-> B (bidirectional)
        network.bbmds["A"] = BBMD(
            address="A",
            bdt=[BDTEntry(address="B"), BDTEntry(address="C")]
        )
        network.bbmds["B"] = BBMD(
            address="B",
            bdt=[BDTEntry(address="A")]
        )
        network.bbmds["C"] = BBMD(
            address="C",
            bdt=[]
        )

        assert network.has_bidirectional_link("A", "B")
        assert network.has_bidirectional_link("B", "A")
        assert not network.has_bidirectional_link("A", "C")

    def test_to_dict_from_dict(self):
        network = BBMDNetwork()
        network.bbmds["A"] = BBMD(
            address="A",
            bdt=[BDTEntry(address="B")]
        )

        d = network.to_dict()
        restored = BBMDNetwork.from_dict(d)

        assert "A" in restored.bbmds
        assert restored.bbmds["A"].bdt[0].address == "B"


class TestAuditEntry:
    def test_creation(self):
        entry = AuditEntry(
            timestamp=datetime.now(),
            action="add_link",
            bbmd_address="192.168.1.1:47808",
            details={"target": "192.168.1.2:47808"}
        )

        assert entry.action == "add_link"
        assert entry.snapshot_id is None

    def test_to_dict_from_dict(self):
        now = datetime.now()
        entry = AuditEntry(
            timestamp=now,
            action="delete_link",
            bbmd_address="A",
            details={"target": "B"},
            snapshot_id="snap123"
        )

        d = entry.to_dict()
        restored = AuditEntry.from_dict(d)

        assert restored.action == entry.action
        assert restored.snapshot_id == entry.snapshot_id


class TestSnapshot:
    def test_creation(self):
        network = BBMDNetwork()
        network.bbmds["A"] = BBMD(address="A", bdt=[])

        snapshot = Snapshot(
            id="snap123",
            timestamp=datetime.now(),
            description="Test snapshot",
            network_state=network
        )

        assert snapshot.id == "snap123"
        assert "A" in snapshot.network_state.bbmds

    def test_to_dict_from_dict(self):
        network = BBMDNetwork()
        network.bbmds["A"] = BBMD(address="A", bdt=[BDTEntry(address="B")])

        snapshot = Snapshot(
            id="snap456",
            timestamp=datetime.now(),
            description="Another snapshot",
            network_state=network
        )

        d = snapshot.to_dict()
        restored = Snapshot.from_dict(d)

        assert restored.id == snapshot.id
        assert restored.description == snapshot.description
        assert "A" in restored.network_state.bbmds
