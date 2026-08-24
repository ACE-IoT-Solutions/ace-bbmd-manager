"""Network topology mutation coverage."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

from bbmd_manager.client import bdt_entry_address
from bbmd_manager.models import BBMD, BBMDNetwork, BDTEntry
from bbmd_manager.network import NetworkManager


OLD = "192.168.10.10:47808"
NEW = "192.168.10.20:47808"
PEER = "192.168.20.10:47808"


def replacement_network() -> BBMDNetwork:
    return BBMDNetwork(bbmds={
        OLD: BBMD(
            address=OLD,
            subnet="192.168.10.0/24",
            subnet_verified=True,
            bdt=[
                BDTEntry(OLD, "255.255.255.0"),
                BDTEntry(PEER, "255.255.255.255"),
            ],
        ),
        NEW: BBMD(
            address=NEW,
            subnet="192.168.10.0/24",
            subnet_verified=True,
            bdt=[BDTEntry("10.99.0.1:47808")],
        ),
        PEER: BBMD(
            address=PEER,
            subnet="192.168.20.0/24",
            subnet_verified=True,
            bdt=[
                BDTEntry(OLD, "255.255.255.255"),
                BDTEntry(NEW, "255.255.255.255"),
            ],
        ),
    })


def test_replacement_plan_copies_bdt_updates_peers_and_clears_old_last():
    network = replacement_network()
    manager = NetworkManager(AsyncMock(), network)

    plan = manager.replacement_plan(OLD, NEW)

    assert list(plan) == [NEW, PEER, OLD]
    assert [(entry.address, entry.mask) for entry in plan[NEW]] == [
        (NEW, "255.255.255.0"),
        (PEER, "255.255.255.255"),
    ]
    assert [entry.address for entry in plan[PEER]] == [NEW]
    assert plan[OLD] == []


def test_replacement_requires_same_known_subnet():
    network = replacement_network()
    network.bbmds[NEW].subnet = "192.168.11.0/24"
    manager = NetworkManager(AsyncMock(), network)

    with pytest.raises(ValueError, match="different subnets"):
        manager.replacement_plan(OLD, NEW)


def test_replacement_requires_both_bbmds_in_cached_state():
    network = replacement_network()
    del network.bbmds[NEW]
    manager = NetworkManager(AsyncMock(), network)

    with pytest.raises(ValueError, match="replacement BBMD.*cached state"):
        manager.replacement_plan(OLD, NEW)


def test_replace_applies_replacement_before_peers_and_old_clear():
    asyncio.run(_replace_applies_in_safe_order())


async def _replace_applies_in_safe_order():
    network = replacement_network()
    client = AsyncMock()
    manager = NetworkManager(client, network)

    modified = await manager.replace_bbmd(OLD, NEW)

    assert modified == [NEW, PEER, OLD]
    assert [call.args[0] for call in client.write_bdt.await_args_list] == modified
    assert network.bbmds[OLD].bdt == []
    assert [entry.address for entry in network.bbmds[NEW].bdt] == [NEW, PEER]
    assert [entry.address for entry in network.bbmds[PEER].bdt] == [NEW]


def test_bdt_wire_address_preserves_distribution_mask():
    address: Any = bdt_entry_address(BDTEntry(OLD, "255.255.255.0"))

    assert str(address) == "192.168.10.10"
    assert str(address.netmask) == "255.255.255.0"
    assert address.addrTuple == ("192.168.10.10", 47808)
