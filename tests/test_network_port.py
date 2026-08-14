"""Network Port Object scanning and subnet selection coverage."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from bbmd_manager.network_port import (
    NetworkPortInfo,
    NetworkPortScan,
    NetworkPortScanner,
    default_subnet_for_bbmd,
    network_from_address_mask,
)
from bbmd_manager.client import BBMDClient


def test_network_notation_uses_network_start_and_prefix_length():
    assert network_from_address_mask("192.168.10.42", "255.255.255.0") == (
        "192.168.10.0/24"
    )


def test_scan_matches_npo_ip_to_bbmd_ip():
    scan = NetworkPortScan(
        device_instance=123,
        ports=[
            NetworkPortInfo(1, "10.0.0.2", "255.255.255.0"),
            NetworkPortInfo(2, "192.168.10.42", "255.255.255.0"),
        ],
    )

    assert scan.subnet_for_bbmd("192.168.10.42:47808") == "192.168.10.0/24"


def test_scan_does_not_guess_when_no_npo_matches_bbmd():
    scan = NetworkPortScan(
        device_instance=123,
        ports=[NetworkPortInfo(1, "10.0.0.2", "255.255.255.0")],
    )

    assert scan.subnet_for_bbmd("192.168.10.42:47808") is None


def test_default_subnet_assumes_24_and_uses_network_start():
    assert default_subnet_for_bbmd("192.168.10.42:47808") == "192.168.10.0/24"


def test_network_port_serialization_uses_canonical_network_not_dotted_mask():
    port = NetworkPortInfo(7, "192.168.10.42", "255.255.255.0")

    assert port.to_dict() == {
        "object": "network-port:7",
        "ip_address": "192.168.10.42",
        "network": "192.168.10.0/24",
        "error": None,
    }
    assert NetworkPortInfo.from_dict(port.to_dict()) == port


def test_scanner_enumerates_npos_and_reads_ip_properties():
    asyncio.run(_scan_npos_and_read_ip_properties())


async def _scan_npos_and_read_ip_properties():
    scanner = NetworkPortScanner("192.168.10.5", timeout=1)
    scanner.app = AsyncMock()
    scanner.app.who_is.return_value = [
        SimpleNamespace(
            pduSource="192.168.10.42",
            iAmDeviceIdentifier=("device", 123),
        )
    ]
    scanner._read_object_list = AsyncMock(
        return_value=[("device", 123), ("network-port", 1), ("network-port", 2)]
    )
    scanner.app.read_property.side_effect = [
        b"\x0a\x00\x00\x02",
        b"\xff\xff\xff\x00",
        b"\xc0\xa8\x0a\x2a",
        b"\xff\xff\xff\x00",
    ]

    result = await scanner.scan("192.168.10.42:47808")

    assert result.device_instance == 123
    assert [port.instance for port in result.ports] == [1, 2]
    assert result.subnet_for_bbmd("192.168.10.42:47808") == "192.168.10.0/24"
    assert scanner.app.read_property.await_count == 4


def test_bdt_read_attaches_matching_npo_subnet():
    asyncio.run(_bdt_read_attaches_matching_npo_subnet())


async def _bdt_read_attaches_matching_npo_subnet():
    client = BBMDClient("192.168.10.5")
    client._ase = AsyncMock()
    client._ase.send_request.return_value = ("bdt_ack", [])
    client._npo_scanner = AsyncMock()
    client._npo_scanner.scan.return_value = NetworkPortScan(
        device_instance=123,
        ports=[NetworkPortInfo(2, "192.168.10.42", "255.255.255.0")],
    )

    bbmd = await client.read_bdt("192.168.10.42")

    assert bbmd.device_instance == 123
    assert bbmd.subnet == "192.168.10.0/24"
    assert bbmd.npo_scan_error is None


def test_bdt_read_falls_back_to_24_when_npo_scan_fails():
    asyncio.run(_bdt_read_falls_back_to_24_when_npo_scan_fails())


async def _bdt_read_falls_back_to_24_when_npo_scan_fails():
    client = BBMDClient("192.168.10.5")
    client._ase = AsyncMock()
    client._ase.send_request.return_value = ("bdt_ack", [])
    client._npo_scanner = AsyncMock()
    client._npo_scanner.scan.side_effect = TimeoutError("NPOs unavailable")

    bbmd = await client.read_bdt("192.168.10.42:47808")

    assert bbmd.subnet == "192.168.10.0/24"
    assert bbmd.npo_scan_error == "NPOs unavailable"


def test_bdt_read_falls_back_to_24_when_no_npo_matches():
    asyncio.run(_bdt_read_falls_back_to_24_when_no_npo_matches())


async def _bdt_read_falls_back_to_24_when_no_npo_matches():
    client = BBMDClient("192.168.10.5")
    client._ase = AsyncMock()
    client._ase.send_request.return_value = ("bdt_ack", [])
    client._npo_scanner = AsyncMock()
    client._npo_scanner.scan.return_value = NetworkPortScan(
        device_instance=123,
        ports=[NetworkPortInfo(1, "10.0.0.1", "255.255.255.0")],
    )

    bbmd = await client.read_bdt("192.168.10.42:47808")

    assert bbmd.subnet == "192.168.10.0/24"
