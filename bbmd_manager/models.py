"""Data models for BBMD Manager."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set
import json


@dataclass
class BDTEntry:
    """A single entry in a Broadcast Distribution Table."""
    address: str  # IP:port format, e.g., "192.168.1.1:47808"
    mask: str = "255.255.255.255"  # Broadcast distribution mask

    def __hash__(self):
        return hash((self.address, self.mask))

    def __eq__(self, other):
        if not isinstance(other, BDTEntry):
            return False
        return self.address == other.address and self.mask == other.mask

    def to_dict(self) -> dict:
        return {"address": self.address, "mask": self.mask}

    @classmethod
    def from_dict(cls, data: dict) -> "BDTEntry":
        return cls(address=data["address"], mask=data.get("mask", "255.255.255.255"))


@dataclass
class BBMD:
    """Represents a BBMD and its BDT."""
    address: str  # IP:port format
    bdt: List[BDTEntry] = field(default_factory=list)
    last_read: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "bdt": [e.to_dict() for e in self.bdt],
            "last_read": self.last_read.isoformat() if self.last_read else None
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BBMD":
        return cls(
            address=data["address"],
            bdt=[BDTEntry.from_dict(e) for e in data.get("bdt", [])],
            last_read=datetime.fromisoformat(data["last_read"]) if data.get("last_read") else None
        )

    def get_peer_addresses(self) -> Set[str]:
        """Get all peer BBMD addresses from the BDT."""
        return {e.address for e in self.bdt if e.address != self.address}


@dataclass
class BBMDNetwork:
    """Represents the entire network of BBMDs and their relationships."""
    bbmds: Dict[str, BBMD] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "bbmds": {addr: bbmd.to_dict() for addr, bbmd in self.bbmds.items()}
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BBMDNetwork":
        return cls(
            bbmds={addr: BBMD.from_dict(b) for addr, b in data.get("bbmds", {}).items()}
        )

    def get_links(self) -> List[tuple]:
        """Get all directed links in the network as (source, destination) tuples."""
        links = []
        for addr, bbmd in self.bbmds.items():
            for entry in bbmd.bdt:
                if entry.address != addr:
                    links.append((addr, entry.address))
        return links

    def has_bidirectional_link(self, addr_a: str, addr_b: str) -> bool:
        """Check if there's a bidirectional link between two BBMDs."""
        if addr_a not in self.bbmds or addr_b not in self.bbmds:
            return False

        a_has_b = any(e.address == addr_b for e in self.bbmds[addr_a].bdt)
        b_has_a = any(e.address == addr_a for e in self.bbmds[addr_b].bdt)

        return a_has_b and b_has_a


@dataclass
class AuditEntry:
    """A single audit log entry."""
    timestamp: datetime
    action: str  # "read_bdt", "write_bdt", "add_link", "delete_link", etc.
    bbmd_address: str
    details: dict
    snapshot_id: Optional[str] = None  # Reference to snapshot before change

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "bbmd_address": self.bbmd_address,
            "details": self.details,
            "snapshot_id": self.snapshot_id
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEntry":
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            action=data["action"],
            bbmd_address=data["bbmd_address"],
            details=data["details"],
            snapshot_id=data.get("snapshot_id")
        )


@dataclass
class Snapshot:
    """A snapshot of network state for rollback capability."""
    id: str
    timestamp: datetime
    description: str
    network_state: BBMDNetwork

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "network_state": self.network_state.to_dict()
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Snapshot":
        return cls(
            id=data["id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            description=data["description"],
            network_state=BBMDNetwork.from_dict(data["network_state"])
        )
