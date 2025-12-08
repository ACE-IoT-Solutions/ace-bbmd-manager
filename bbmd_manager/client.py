"""BACnet BBMD client for reading and writing BDTs using bacpypes3."""

import asyncio
from datetime import datetime
from typing import List, Optional

from bacpypes3.comm import bind, ApplicationServiceElement
from bacpypes3.pdu import IPv4Address
from bacpypes3.ipv4.bvll import (
    LPDU,
    ReadBroadcastDistributionTable,
    ReadBroadcastDistributionTableAck,
    WriteBroadcastDistributionTable,
    Result,
    BVLLCodec,
)
from bacpypes3.ipv4.service import BIPNormal, UDPMultiplexer
from bacpypes3.ipv4 import IPv4DatagramServer

from .models import BDTEntry, BBMD


class BBMDClientError(Exception):
    """Base exception for BBMD client errors."""
    pass


class BVLLServiceElement(ApplicationServiceElement):
    """Service element for handling BVLL request/response patterns."""

    def __init__(self, debug: bool = False):
        self._pending_futures: dict = {}
        self._debug = debug
        self._future_id = 0

    def _debug_print(self, msg: str):
        """Print debug message if debug mode is on."""
        if self._debug:
            print(f"[DEBUG] {msg}")

    async def confirmation(self, pdu: LPDU):
        """Handle incoming BVLL responses."""
        self._debug_print(f"Received PDU type: {type(pdu).__name__}")

        if self._debug:
            self._debug_print("PDU attributes:")
            for attr in dir(pdu):
                if not attr.startswith('_') and not callable(getattr(pdu, attr, None)):
                    try:
                        val = getattr(pdu, attr)
                        self._debug_print(f"  {attr} = {val}")
                    except Exception:
                        pass

        # Get the source address to match with pending request
        source = str(pdu.pduSource) if pdu.pduSource else None
        self._debug_print(f"Response from: {source}")

        # Find matching pending future
        future = None
        future_key = None
        for key, (fut, addr) in list(self._pending_futures.items()):
            if addr == source:
                future = fut
                future_key = key
                break

        if future is None:
            self._debug_print(f"No pending future for response from {source}")
            return

        if isinstance(pdu, ReadBroadcastDistributionTableAck):
            future.set_result(("bdt_ack", pdu.bvlciBDT))
        elif isinstance(pdu, Result):
            future.set_result(("result", pdu.bvlciResultCode))
        else:
            future.set_result(("unknown", pdu))

        if future_key:
            del self._pending_futures[future_key]

    async def send_request(self, pdu: LPDU, timeout: float = 5.0):
        """Send a BVLL request and wait for response."""
        dest = str(pdu.pduDestination)
        self._debug_print(f"Sending request to {dest}")

        # Create a future for the response
        self._future_id += 1
        future = asyncio.Future()
        self._pending_futures[self._future_id] = (future, dest)

        # Send the request
        await self.request(pdu)

        try:
            result = await asyncio.wait_for(future, timeout=timeout)
            return result
        except asyncio.TimeoutError:
            # Clean up pending future
            if self._future_id in self._pending_futures:
                del self._pending_futures[self._future_id]
            return None


class BBMDClient:
    """Client for communicating with BBMDs to read/write BDTs using bacpypes3."""

    def __init__(self, local_address: str, timeout: float = 5.0, debug: bool = False):
        """
        Initialize the BBMD client.

        Args:
            local_address: Local IP address to bind to (e.g., "192.168.1.100")
            timeout: Timeout in seconds for operations
            debug: Enable debug output
        """
        self.local_address = local_address
        self.timeout = timeout
        self.debug = debug
        self._link_layer = None
        self._ase = None

    def _debug_print(self, msg: str):
        """Print debug message if debug mode is on."""
        if self.debug:
            print(f"[DEBUG] {msg}")

    async def start(self):
        """Start the BACnet communication stack."""
        # Normalize address to include port if not present
        addr_str = self.local_address
        if ":" not in addr_str:
            addr_str = f"{addr_str}:47808"

        self._debug_print(f"Binding to local address: {addr_str}")

        # Create the IPv4 address
        local_addr = IPv4Address(addr_str)

        # Build a minimal BVLL link layer stack like NormalLinkLayer does:
        # BIPNormal -> BVLLCodec -> UDPMultiplexer.annexJ
        # UDPMultiplexer -> IPv4DatagramServer
        self._bip = BIPNormal()
        self._codec = BVLLCodec()
        self._multiplexer = UDPMultiplexer()
        self._server = IPv4DatagramServer(local_addr)

        # Bind the stack together
        bind(self._bip, self._codec, self._multiplexer.annexJ)
        bind(self._multiplexer, self._server)

        # Create our service element and bind it to the BIPNormal (which is a SAP)
        self._ase = BVLLServiceElement(debug=self.debug)
        bind(self._ase, self._bip)

        self._debug_print("Stack initialized")

    async def stop(self):
        """Stop the BACnet communication stack."""
        if self._server:
            self._server.close()
            self._server = None
        self._bip = None
        self._codec = None
        self._multiplexer = None
        self._ase = None

    async def read_bdt(self, bbmd_address: str) -> BBMD:
        """
        Read the BDT from a BBMD.

        Args:
            bbmd_address: Address of the BBMD (e.g., "192.168.1.1:47808" or "192.168.1.1")

        Returns:
            BBMD object with populated BDT

        Raises:
            BBMDClientError: If read fails or times out
        """
        # Normalize address
        if ":" not in bbmd_address:
            bbmd_address = f"{bbmd_address}:47808"

        self._debug_print(f"Reading BDT from {bbmd_address}")

        dest_addr = IPv4Address(bbmd_address)
        request = ReadBroadcastDistributionTable(destination=dest_addr)

        result = await self._ase.send_request(request, timeout=self.timeout)

        if result is None:
            raise BBMDClientError(f"Timeout reading BDT from {bbmd_address}")

        result_type, result_data = result

        if result_type == "result":
            raise BBMDClientError(f"Error reading BDT from {bbmd_address}: result code {result_data}")

        if result_type != "bdt_ack":
            raise BBMDClientError(f"Unexpected response type from {bbmd_address}: {result_type}")

        # Parse the BDT entries
        bdt_entries = []
        bdt_list = result_data

        self._debug_print("Parsing response...")
        self._debug_print(f"bvlciBDT = {bdt_list}")
        self._debug_print(f"bvlciBDT len = {len(bdt_list) if bdt_list else 0}")

        if bdt_list:
            for entry in bdt_list:
                self._debug_print(f"  Entry: {entry}, type: {type(entry)}")
                # Entry is an IPv4Address object
                addr_str = str(entry)
                # Normalize address to always include port
                if ":" not in addr_str:
                    addr_str = f"{addr_str}:47808"
                # bacpypes3 uses IPv4Address which includes mask info
                mask = getattr(entry, 'addrMask', 0xFFFFFFFF)
                if isinstance(mask, int):
                    mask_str = f"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}"
                else:
                    mask_str = str(mask) if mask else "255.255.255.255"
                bdt_entries.append(BDTEntry(address=addr_str, mask=mask_str))
                self._debug_print(f"    Parsed: {addr_str} mask {mask_str}")

        self._debug_print(f"Total BDT entries parsed: {len(bdt_entries)}")

        return BBMD(
            address=bbmd_address,
            bdt=bdt_entries,
            last_read=datetime.now()
        )

    async def write_bdt(self, bbmd_address: str, bdt_entries: List[BDTEntry]) -> bool:
        """
        Write a BDT to a BBMD.

        Args:
            bbmd_address: Address of the BBMD
            bdt_entries: List of BDT entries to write

        Returns:
            True if successful

        Raises:
            BBMDClientError: If write fails
        """
        # Normalize address
        if ":" not in bbmd_address:
            bbmd_address = f"{bbmd_address}:47808"

        self._debug_print(f"Writing BDT to {bbmd_address}")

        # Build the BDT list
        bdt = []
        for entry in bdt_entries:
            bdt.append(IPv4Address(entry.address))

        dest_addr = IPv4Address(bbmd_address)
        request = WriteBroadcastDistributionTable(destination=dest_addr, bdt=bdt)

        result = await self._ase.send_request(request, timeout=self.timeout)

        if result is None:
            raise BBMDClientError(f"Timeout writing BDT to {bbmd_address}")

        result_type, result_data = result

        if result_type == "result":
            if result_data != 0:
                raise BBMDClientError(f"Error writing BDT to {bbmd_address}: result code {result_data}")
            return True

        raise BBMDClientError(f"Unexpected response type from {bbmd_address}: {result_type}")

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()
        return False
