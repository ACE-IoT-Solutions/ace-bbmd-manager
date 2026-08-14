"""Discover BACnet Network Port Objects associated with a BBMD."""

import asyncio
from dataclasses import dataclass
import ipaddress
import math
from typing import Any, List, Optional, Tuple

from bacpypes3.ipv4.app import NormalApplication
from bacpypes3.local.device import DeviceObject
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import ObjectIdentifier


NETWORK_PORT_OBJECT_TYPE = 56
DEFAULT_SUBNET_PREFIX = 24


def _object_identifier_parts(value: Any) -> Tuple[Any, int]:
    """Return an object identifier as an ``(object_type, instance)`` tuple."""
    if hasattr(value, "value"):
        value = value.value
    return value[0], int(value[1])


def _is_network_port(object_type: Any) -> bool:
    try:
        return int(object_type) == NETWORK_PORT_OBJECT_TYPE
    except (TypeError, ValueError):
        return str(object_type).replace("_", "-").lower() == "network-port"


def _ipv4_text(value: Any) -> str:
    """Decode a BACnet IPv4 octet string into ordinary dotted notation."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return str(ipaddress.IPv4Address(bytes(value)))
    return str(ipaddress.IPv4Address(str(value)))


def network_from_address_mask(address: str, mask: str) -> str:
    """Return canonical ``network-address/prefix-length`` notation."""
    return str(ipaddress.IPv4Network(f"{address}/{mask}", strict=False))


def default_subnet_for_bbmd(bbmd_address: str) -> str:
    """Return the legacy /24 subnet assumption for a BBMD endpoint."""
    bbmd_ip = bbmd_address.split(":", 1)[0]
    return str(
        ipaddress.IPv4Network(
            f"{bbmd_ip}/{DEFAULT_SUBNET_PREFIX}", strict=False
        )
    )


@dataclass(frozen=True)
class NetworkPortInfo:
    """The IPv4 addressing properties needed to identify a BBMD subnet."""

    instance: int
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    error: Optional[str] = None

    @property
    def network(self) -> Optional[str]:
        if not self.ip_address or not self.subnet_mask:
            return None
        try:
            return network_from_address_mask(self.ip_address, self.subnet_mask)
        except ValueError:
            return None

    def to_dict(self) -> dict:
        return {
            "object": f"network-port:{self.instance}",
            "ip_address": self.ip_address,
            "network": self.network,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NetworkPortInfo":
        network = data.get("network")
        return cls(
            instance=int(data.get("instance", str(data.get("object", "0:0")).split(":")[-1])),
            ip_address=data.get("ip_address"),
            subnet_mask=(
                str(ipaddress.IPv4Network(network).netmask) if network else data.get("subnet_mask")
            ),
            error=data.get("error"),
        )


@dataclass(frozen=True)
class NetworkPortScan:
    """Network Port Object inventory returned for a BBMD endpoint."""

    device_instance: int
    ports: List[NetworkPortInfo]

    def subnet_for_bbmd(self, bbmd_address: str) -> Optional[str]:
        bbmd_ip = str(ipaddress.IPv4Address(bbmd_address.split(":", 1)[0]))
        for port in self.ports:
            if port.ip_address == bbmd_ip:
                return port.network
        return None


class NetworkPortScanner:
    """Use BACnet application services to inspect Network Port Objects."""

    def __init__(self, local_address: str, timeout: float = 5.0):
        self.local_address = local_address
        self.timeout = timeout
        self.app: Optional[NormalApplication] = None

    async def start(self) -> None:
        local_ip = self.local_address.split("/", 1)[0].split(":", 1)[0]
        device = DeviceObject(
            objectIdentifier=("device", 4194302),
            objectName="ace-bbmd-manager",
            vendorIdentifier=0,
        )
        self.app = NormalApplication(device, Address(f"{local_ip}:0"))
        try:
            server = self.app.normal.server
            transport_tasks = getattr(server, "_transport_tasks", ())
            if transport_tasks:
                await asyncio.wait_for(
                    server._local_transport_ready.wait(), timeout=self.timeout
                )
        except Exception:
            self.app.close()
            self.app = None
            raise

    async def stop(self) -> None:
        if self.app is not None:
            self.app.close()
            self.app = None

    async def _read_object_list(
        self, address: Address, device_object: Any
    ) -> List[Any]:
        """Read objectList whole, with an array-element fallback."""
        assert self.app is not None
        try:
            value = await asyncio.wait_for(
                self.app.read_property(address, device_object, "object-list"),
                timeout=self.timeout,
            )
            if isinstance(value, list):
                return value
        except Exception:
            pass

        count = await asyncio.wait_for(
            self.app.read_property(address, device_object, "object-list", array_index=0),
            timeout=self.timeout,
        )
        objects = []
        for index in range(1, int(count) + 1):
            objects.append(
                await asyncio.wait_for(
                    self.app.read_property(
                        address, device_object, "object-list", array_index=index
                    ),
                    timeout=self.timeout,
                )
            )
        return objects

    async def scan(self, bbmd_address: str) -> NetworkPortScan:
        """Discover the BBMD device and read IPv4 data from all of its NPOs."""
        if self.app is None:
            raise RuntimeError("network port scanner is not started")

        target = Address(bbmd_address)
        responses = await self.app.who_is(
            None, None, target, timeout=max(1, math.ceil(self.timeout))
        )
        matching_responses = [
            response
            for response in responses or []
            if getattr(response, "pduSource", None) is not None
            and str(response.pduSource).split(":", 1)[0]
            == bbmd_address.split(":", 1)[0]
        ]
        if not matching_responses:
            raise TimeoutError(f"no BACnet device answered from {bbmd_address}")

        _, device_instance = _object_identifier_parts(
            matching_responses[0].iAmDeviceIdentifier
        )
        device_object = ObjectIdentifier(("device", device_instance))
        object_list = await self._read_object_list(target, device_object)

        ports: List[NetworkPortInfo] = []
        for object_id in object_list:
            object_type, instance = _object_identifier_parts(object_id)
            if not _is_network_port(object_type):
                continue
            try:
                ip_value, mask_value = await asyncio.gather(
                    asyncio.wait_for(
                        self.app.read_property(target, object_id, "ip-address"),
                        timeout=self.timeout,
                    ),
                    asyncio.wait_for(
                        self.app.read_property(target, object_id, "ip-subnet-mask"),
                        timeout=self.timeout,
                    ),
                )
                ports.append(
                    NetworkPortInfo(
                        instance=instance,
                        ip_address=_ipv4_text(ip_value),
                        subnet_mask=_ipv4_text(mask_value),
                    )
                )
            except Exception as error:
                ports.append(NetworkPortInfo(instance=instance, error=str(error)))

        return NetworkPortScan(device_instance=device_instance, ports=ports)
