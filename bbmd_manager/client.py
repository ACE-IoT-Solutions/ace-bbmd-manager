"""BACnet BBMD client for reading and writing BDTs."""

import threading
import time
from datetime import datetime
from typing import Callable, List, Optional

from bacpypes.comm import Client, bind
from bacpypes.core import run, stop, enable_sleeping, deferred
from bacpypes.pdu import Address
from bacpypes.bvll import (
    ReadBroadcastDistributionTable,
    ReadBroadcastDistributionTableAck,
    WriteBroadcastDistributionTable,
    Result,
)
from bacpypes.bvllservice import AnnexJCodec, UDPMultiplexer
from bacpypes.task import TaskManager

from .models import BDTEntry, BBMD


class BBMDClientError(Exception):
    """Base exception for BBMD client errors."""
    pass


class BBMDClient(Client):
    """Client for communicating with BBMDs to read/write BDTs."""

    def __init__(self, local_address: str, timeout: float = 5.0, debug: bool = False):
        """
        Initialize the BBMD client.

        Args:
            local_address: Local IP address to bind to (e.g., "192.168.1.100")
            timeout: Timeout in seconds for operations
            debug: Enable debug output
        """
        Client.__init__(self)
        self.local_address = local_address
        self.timeout = timeout
        self.debug = debug
        self._response = None
        self._response_event = threading.Event()
        self._running = False
        self._thread = None
        self._annexj = None
        self._mux = None
        self._pending_request = None

    def _debug_print(self, msg: str):
        """Print debug message if debug mode is on."""
        if self.debug:
            print(f"[DEBUG] {msg}")

    def start(self):
        """Start the BACnet communication stack."""
        if self._running:
            return

        # Create the address
        addr = Address(self.local_address)
        self._debug_print(f"Binding to local address: {addr}")

        # Create codec and multiplexer
        self._annexj = AnnexJCodec()
        self._mux = UDPMultiplexer(addr)

        # Bind the layers
        bind(self, self._annexj, self._mux.annexJ)

        # Enable sleeping for thread safety
        enable_sleeping()

        # Start the core in a background thread
        self._running = True
        self._thread = threading.Thread(target=self._run_core, daemon=True)
        self._thread.start()

        # Give it a moment to start
        time.sleep(0.2)

    def _run_core(self):
        """Run the BACpypes core in background thread."""
        try:
            run()
        except Exception as e:
            self._debug_print(f"Core exception: {e}")
        finally:
            self._running = False

    def stop(self):
        """Stop the BACnet communication stack."""
        if self._running:
            self._running = False
            stop()
            if self._thread:
                self._thread.join(timeout=2.0)

    def confirmation(self, pdu):
        """Handle incoming PDUs (responses)."""
        self._debug_print(f"Received PDU type: {type(pdu).__name__}")

        # Debug: print all attributes
        if self.debug:
            self._debug_print(f"PDU attributes:")
            for attr in dir(pdu):
                if not attr.startswith('_') and not callable(getattr(pdu, attr, None)):
                    try:
                        val = getattr(pdu, attr)
                        self._debug_print(f"  {attr} = {val}")
                    except:
                        pass

        self._response = pdu
        self._response_event.set()

    def _send_and_wait(self, pdu) -> Optional[object]:
        """Send a PDU and wait for response."""
        self._response = None
        self._response_event.clear()

        self._debug_print(f"Sending request to {pdu.pduDestination}")

        # Send the request
        self.request(pdu)

        # Wait for response
        if self._response_event.wait(timeout=self.timeout):
            return self._response

        self._debug_print("Timeout waiting for response")
        return None

    def read_bdt(self, bbmd_address: str) -> BBMD:
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

        request = ReadBroadcastDistributionTable(destination=Address(bbmd_address))
        response = self._send_and_wait(request)

        if response is None:
            raise BBMDClientError(f"Timeout reading BDT from {bbmd_address}")

        if isinstance(response, Result):
            raise BBMDClientError(f"Error reading BDT from {bbmd_address}: result code {response.bvlciResultCode}")

        if not isinstance(response, ReadBroadcastDistributionTableAck):
            raise BBMDClientError(f"Unexpected response type from {bbmd_address}: {type(response)}")

        # Parse the BDT entries - bacpypes stores them in bvlciBDT
        bdt_entries = []

        self._debug_print(f"Parsing response...")
        self._debug_print(f"Has bvlciBDT attr: {hasattr(response, 'bvlciBDT')}")

        if hasattr(response, 'bvlciBDT'):
            bdt_list = response.bvlciBDT
            self._debug_print(f"bvlciBDT = {bdt_list}")
            self._debug_print(f"bvlciBDT type = {type(bdt_list)}")
            self._debug_print(f"bvlciBDT len = {len(bdt_list) if bdt_list else 0}")

            if bdt_list:
                for entry in bdt_list:
                    # Entry is an Address object with addrMask attribute
                    self._debug_print(f"  Entry: {entry}, type: {type(entry)}")
                    addr_str = str(entry)
                    mask = getattr(entry, 'addrMask', 0xFFFFFFFF)
                    # Convert mask int to dotted notation
                    mask_str = f"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}"
                    bdt_entries.append(BDTEntry(address=addr_str, mask=mask_str))
                    self._debug_print(f"    Parsed: {addr_str} mask {mask_str}")

        self._debug_print(f"Total BDT entries parsed: {len(bdt_entries)}")

        return BBMD(
            address=bbmd_address,
            bdt=bdt_entries,
            last_read=datetime.now()
        )

    def write_bdt(self, bbmd_address: str, bdt_entries: List[BDTEntry]) -> bool:
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

        # Build the BDT list
        bdt = []
        for entry in bdt_entries:
            bdt.append(Address(entry.address))

        request = WriteBroadcastDistributionTable(
            destination=Address(bbmd_address),
            bdt=bdt
        )

        response = self._send_and_wait(request)

        if response is None:
            raise BBMDClientError(f"Timeout writing BDT to {bbmd_address}")

        if isinstance(response, Result):
            if response.bvlciResultCode != 0:
                raise BBMDClientError(f"Error writing BDT to {bbmd_address}: result code {response.bvlciResultCode}")
            return True

        raise BBMDClientError(f"Unexpected response type from {bbmd_address}: {type(response)}")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False
