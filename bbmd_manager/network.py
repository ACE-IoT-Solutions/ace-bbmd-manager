"""Network walking and topology management for BBMD networks."""

from datetime import datetime
from typing import Callable, Dict, List, Optional, Set

from .client import BBMDClient, BBMDClientError
from .models import BBMD, BBMDNetwork, BDTEntry


def normalize_bbmd_address(address: str) -> str:
    """Return the canonical ``IP:port`` form used by cached state."""
    return address if ":" in address else f"{address}:47808"


def _replace_bdt_address(
    entries: List[BDTEntry], old_address: str, new_address: str
) -> List[BDTEntry]:
    """Replace an address while preserving masks and removing duplicates."""
    result = []
    seen = set()
    for entry in entries:
        address = new_address if entry.address == old_address else entry.address
        if address in seen:
            continue
        result.append(BDTEntry(address=address, mask=entry.mask))
        seen.add(address)
    return result


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

    def replacement_plan(
        self, existing: str, replacement: str
    ) -> Dict[str, List[BDTEntry]]:
        """Build the final BDTs required to replace one BBMD with another."""
        existing = normalize_bbmd_address(existing)
        replacement = normalize_bbmd_address(replacement)

        if existing == replacement:
            raise ValueError("existing and replacement BBMDs must be different")
        if existing not in self.network.bbmds:
            raise ValueError(f"existing BBMD {existing} is not in cached state")
        if replacement not in self.network.bbmds:
            raise ValueError(f"replacement BBMD {replacement} is not in cached state")

        existing_bbmd = self.network.bbmds[existing]
        replacement_bbmd = self.network.bbmds[replacement]
        if not existing_bbmd.subnet or not replacement_bbmd.subnet:
            raise ValueError(
                "both BBMDs must have subnet data; run 'read' for each BBMD first"
            )
        if existing_bbmd.subnet != replacement_bbmd.subnet:
            raise ValueError(
                f"BBMDs are on different subnets ({existing_bbmd.subnet} and "
                f"{replacement_bbmd.subnet})"
            )

        plan: Dict[str, List[BDTEntry]] = {}

        # Bring up the replacement before modifying peers or clearing the old
        # BBMD.  Rewrite a copied self-entry and retain every distribution mask.
        replacement_entries = _replace_bdt_address(
            existing_bbmd.bdt, existing, replacement
        )
        if replacement_bbmd.bdt != replacement_entries:
            plan[replacement] = replacement_entries

        # Replace the old endpoint everywhere it is referenced.  The old and
        # replacement BBMDs have dedicated final states above/below.
        for peer_address, peer in sorted(self.network.bbmds.items()):
            if peer_address in (existing, replacement):
                continue
            if any(entry.address == existing for entry in peer.bdt):
                plan[peer_address] = _replace_bdt_address(
                    peer.bdt, existing, replacement
                )

        # Clear the old BBMD only after the replacement and peers are ready.
        if existing_bbmd.bdt:
            plan[existing] = []

        return plan

    async def replace_bbmd(self, existing: str, replacement: str) -> List[str]:
        """Apply a cached-state replacement plan in interruption-safe order."""
        plan = self.replacement_plan(existing, replacement)
        modified = []
        for address, entries in plan.items():
            await self.client.write_bdt(address, entries)
            self.network.bbmds[address].bdt = list(entries)
            modified.append(address)
        return modified

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
