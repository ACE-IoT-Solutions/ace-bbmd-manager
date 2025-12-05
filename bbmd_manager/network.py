"""Network walking and topology management for BBMD networks."""

from datetime import datetime
from typing import Callable, List, Optional, Set

from .client import BBMDClient, BBMDClientError
from .models import BBMD, BBMDNetwork, BDTEntry


class NetworkWalker:
    """Walks a network of BBMDs to discover topology."""

    def __init__(self, client: BBMDClient, progress_callback: Optional[Callable[[str], None]] = None):
        """
        Initialize the network walker.

        Args:
            client: BBMDClient instance for communication
            progress_callback: Optional callback for progress updates
        """
        self.client = client
        self.progress_callback = progress_callback

    def _log(self, message: str):
        """Log a message via callback if available."""
        if self.progress_callback:
            self.progress_callback(message)

    async def walk(self, seed_addresses: List[str], max_depth: int = 10) -> BBMDNetwork:
        """
        Walk the BBMD network starting from seed addresses.

        Args:
            seed_addresses: List of BBMD addresses to start from
            max_depth: Maximum depth to traverse (prevents infinite loops)

        Returns:
            BBMDNetwork containing all discovered BBMDs and their BDTs
        """
        network = BBMDNetwork()
        visited: Set[str] = set()
        to_visit: Set[str] = set()

        # Normalize seed addresses
        for addr in seed_addresses:
            if ":" not in addr:
                addr = f"{addr}:47808"
            to_visit.add(addr)

        depth = 0
        while to_visit and depth < max_depth:
            current_batch = list(to_visit)
            to_visit = set()

            for address in current_batch:
                if address in visited:
                    continue

                visited.add(address)
                self._log(f"Reading BDT from {address}...")

                try:
                    bbmd = await self.client.read_bdt(address)
                    network.bbmds[address] = bbmd
                    self._log(f"  Found {len(bbmd.bdt)} entries in BDT")

                    # Queue up newly discovered peers
                    for entry in bbmd.bdt:
                        peer_addr = entry.address
                        if peer_addr not in visited:
                            to_visit.add(peer_addr)

                except BBMDClientError as e:
                    self._log(f"  Error: {e}")
                    # Still mark as visited to avoid retrying
                    network.bbmds[address] = BBMD(address=address, bdt=[], last_read=datetime.now())

            depth += 1

        self._log(f"Walk complete. Found {len(network.bbmds)} BBMDs.")
        return network


class NetworkManager:
    """Manages changes to BBMD network topology."""

    def __init__(self, client: BBMDClient, network: BBMDNetwork):
        """
        Initialize the network manager.

        Args:
            client: BBMDClient instance for communication
            network: Current network state
        """
        self.client = client
        self.network = network

    async def add_link(self, source: str, target: str, bidirectional: bool = False) -> List[str]:
        """
        Add a link from source BBMD to target BBMD.

        Args:
            source: Source BBMD address
            target: Target BBMD address
            bidirectional: If True, also add reverse link

        Returns:
            List of modified BBMD addresses
        """
        modified = []

        # Normalize addresses
        if ":" not in source:
            source = f"{source}:47808"
        if ":" not in target:
            target = f"{target}:47808"

        # Add forward link
        if source in self.network.bbmds:
            bbmd = self.network.bbmds[source]
            if not any(e.address == target for e in bbmd.bdt):
                new_bdt = list(bbmd.bdt) + [BDTEntry(address=target)]
                await self.client.write_bdt(source, new_bdt)
                bbmd.bdt = new_bdt
                modified.append(source)

        # Add reverse link if bidirectional
        if bidirectional and target in self.network.bbmds:
            bbmd = self.network.bbmds[target]
            if not any(e.address == source for e in bbmd.bdt):
                new_bdt = list(bbmd.bdt) + [BDTEntry(address=source)]
                await self.client.write_bdt(target, new_bdt)
                bbmd.bdt = new_bdt
                modified.append(target)

        return modified

    async def delete_link(self, source: str, target: str, bidirectional: bool = False) -> List[str]:
        """
        Delete a link from source BBMD to target BBMD.

        Args:
            source: Source BBMD address
            target: Target BBMD address
            bidirectional: If True, also delete reverse link

        Returns:
            List of modified BBMD addresses
        """
        modified = []

        # Normalize addresses
        if ":" not in source:
            source = f"{source}:47808"
        if ":" not in target:
            target = f"{target}:47808"

        # Delete forward link
        if source in self.network.bbmds:
            bbmd = self.network.bbmds[source]
            new_bdt = [e for e in bbmd.bdt if e.address != target]
            if len(new_bdt) != len(bbmd.bdt):
                await self.client.write_bdt(source, new_bdt)
                bbmd.bdt = new_bdt
                modified.append(source)

        # Delete reverse link if bidirectional
        if bidirectional and target in self.network.bbmds:
            bbmd = self.network.bbmds[target]
            new_bdt = [e for e in bbmd.bdt if e.address != source]
            if len(new_bdt) != len(bbmd.bdt):
                await self.client.write_bdt(target, new_bdt)
                bbmd.bdt = new_bdt
                modified.append(target)

        return modified

    async def delete_bbmd(self, address: str) -> List[str]:
        """
        Delete a BBMD from the network (removes it from all other BBMDs' BDTs).

        Args:
            address: Address of the BBMD to remove

        Returns:
            List of modified BBMD addresses
        """
        modified = []

        # Normalize address
        if ":" not in address:
            address = f"{address}:47808"

        # Remove from all other BBMDs
        for bbmd_addr, bbmd in self.network.bbmds.items():
            if bbmd_addr == address:
                continue

            new_bdt = [e for e in bbmd.bdt if e.address != address]
            if len(new_bdt) != len(bbmd.bdt):
                await self.client.write_bdt(bbmd_addr, new_bdt)
                bbmd.bdt = new_bdt
                modified.append(bbmd_addr)

        # Clear the deleted BBMD's BDT
        if address in self.network.bbmds:
            bbmd = self.network.bbmds[address]
            if bbmd.bdt:
                await self.client.write_bdt(address, [])
                bbmd.bdt = []
                modified.append(address)

        return modified

    async def set_bdt(self, address: str, entries: List[BDTEntry]) -> bool:
        """
        Set the complete BDT for a BBMD.

        Args:
            address: BBMD address
            entries: List of BDT entries to set

        Returns:
            True if successful
        """
        # Normalize address
        if ":" not in address:
            address = f"{address}:47808"

        await self.client.write_bdt(address, entries)

        if address in self.network.bbmds:
            self.network.bbmds[address].bdt = entries

        return True
