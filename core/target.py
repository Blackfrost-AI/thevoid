"""THE VOID — Target: The target abstraction for the agent.

Every target is a victim. The agent doesn't choose — it hunts.
This module provides target abstraction for IP, domain, network, and scope.
"""

import ipaddress
import re
import logging
from typing import Any, Dict, List, Optional, Union
from enum import Enum

logger = logging.getLogger("void.target")


class TargetType(Enum):
    """Types of targets."""
    IP = "ip"
    DOMAIN = "domain"
    NETWORK = "network"
    URL = "url"
    SUBNET = "subnet"
    HOSTNAME = "hostname"
    UNKNOWN = "unknown"


class Target:
    """A single target — an IP, domain, or network to attack."""

    def __init__(self, value: str = "", target_type: Optional[TargetType] = None,
                 name: Optional[str] = None, tags: Optional[List[str]] = None,
                 metadata: Optional[Dict[str, Any]] = None,
                 host: Optional[str] = None):
        """Initialize a target.

        Args:
            value: Target value (IP, domain, URL, etc.)
            target_type: Type of target (auto-detected if not provided)
            name: Human-readable name
            tags: Optional tags
            metadata: Optional metadata
            host: Alias for value (if value not provided)
        """
        if not value and host:
            value = host
        self.value = value.strip()
        self.target_type = target_type or self._detect_type(value)
        self.name = name or value
        self.tags = tags or []
        self.metadata = metadata or {}
        self.discoveries: Dict[str, Any] = {}
        logger.info(f"Target created: {self.name} ({self.target_type.value})")

    def _detect_type(self, value: str) -> TargetType:
        """Auto-detect the target type from the value."""
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            return TargetType.IP
        if "/" in value and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+$", value):
            return TargetType.SUBNET
        if value.startswith("http://") or value.startswith("https://"):
            return TargetType.URL
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$", value):
            return TargetType.DOMAIN
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", value):
            return TargetType.NETWORK
        return TargetType.HOSTNAME

    def is_ip(self) -> bool:
        return self.target_type == TargetType.IP

    def is_domain(self) -> bool:
        return self.target_type == TargetType.DOMAIN

    def is_network(self) -> bool:
        return self.target_type in (TargetType.NETWORK, TargetType.SUBNET)

    def is_url(self) -> bool:
        return self.target_type == TargetType.URL

    def get_domain(self) -> str:
        """Get the domain from a URL or return the value as-is."""
        if self.is_url():
            # Extract domain from URL
            value = self.value.replace("http://", "").replace("https://", "")
            return value.split("/")[0].split(":")[0]
        return self.value

    def get_ip(self) -> Optional[str]:
        """Get the IP address if available."""
        if self.is_ip():
            return self.value
        if self.is_url():
            value = self.value.replace("http://", "").replace("https://", "")
            host = value.split("/")[0].split(":")[0]
            try:
                ipaddress.ip_address(host)
                return host
            except ValueError:
                return None
        return None

    def add_discovery(self, key: str, value: Any) -> None:
        """Add a discovery to the target."""
        self.discoveries[key] = value
        logger.debug(f"Discovery added to {self.name}: {key} = {str(value)[:100]}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert target to dictionary."""
        return {
            "value": self.value,
            "type": self.target_type.value,
            "name": self.name,
            "tags": self.tags,
            "metadata": self.metadata,
            "discoveries": self.discoveries,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Target":
        """Create a Target from a dictionary."""
        return cls(
            value=data.get("value", ""),
            target_type=TargetType(data.get("type", "unknown")),
            name=data.get("name"),
            tags=data.get("tags"),
            metadata=data.get("metadata"),
        )

    def __repr__(self) -> str:
        return f"Target({self.value}, type={self.target_type.value}, name={self.name})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Target):
            return self.value == other.value and self.target_type == other.target_type
        return False

    def __hash__(self) -> int:
        return hash((self.value, self.target_type))


class TargetGroup:
    """A group of targets — the hunting ground."""

    def __init__(self, name: str, targets: Optional[List[Target]] = None):
        """Initialize a target group.

        Args:
            name: Name of the group
            targets: List of targets
        """
        self.name = name
        self.targets: List[Target] = targets or []
        self.metadata: Dict[str, Any] = {}
        logger.info(f"Target group created: {name} with {len(self.targets)} targets")

    def add_target(self, target: Target) -> None:
        """Add a target to the group."""
        if target not in self.targets:
            self.targets.append(target)

    def remove_target(self, target: Target) -> None:
        """Remove a target from the group."""
        if target in self.targets:
            self.targets.remove(target)

    def get_by_type(self, target_type: TargetType) -> List[Target]:
        """Get all targets of a specific type."""
        return [t for t in self.targets if t.target_type == target_type]

    def get_by_tag(self, tag: str) -> List[Target]:
        """Get all targets with a specific tag."""
        return [t for t in self.targets if tag in t.tags]

    def count(self) -> int:
        return len(self.targets)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "targets": [t.to_dict() for t in self.targets],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TargetGroup":
        targets = [Target.from_dict(t) for t in data.get("targets", [])]
        return cls(name=data.get("name", ""), targets=targets)

    def __repr__(self) -> str:
        return f"TargetGroup({self.name}, {len(self.targets)} targets)"
