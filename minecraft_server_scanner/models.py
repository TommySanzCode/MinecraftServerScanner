from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ScanSettings:
    target_spec: str = "192.168.1.1-192.168.1.255"
    ports: str = "25565,19132-19133"
    edition: str = "both"
    timeout: float = 3.0
    concurrency: int = 64
    retries: int = 0
    min_players: int = 0
    only_online: bool = False

    def normalized_edition(self) -> str:
        value = self.edition.lower().strip()
        if value in {"java", "bedrock", "both"}:
            return value
        raise ValueError("Edition must be java, bedrock, or both.")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, values: Dict[str, Any]) -> "ScanSettings":
        return cls(
            target_spec=str(values.get("target_spec", cls.target_spec)),
            ports=str(values.get("ports", cls.ports)),
            edition=str(values.get("edition", cls.edition)),
            timeout=float(values.get("timeout", cls.timeout)),
            concurrency=int(values.get("concurrency", cls.concurrency)),
            retries=int(values.get("retries", cls.retries)),
            min_players=int(values.get("min_players", cls.min_players)),
            only_online=bool(values.get("only_online", cls.only_online)),
        )


@dataclass
class ScanProfile:
    name: str
    settings: ScanSettings = field(default_factory=ScanSettings)
    id: Optional[int] = None
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)


@dataclass
class ScanRun:
    settings: ScanSettings
    id: Optional[int] = None
    profile_id: Optional[int] = None
    started_at: str = field(default_factory=utc_now)
    finished_at: Optional[str] = None
    status: str = "running"
    total_targets: int = 0
    completed_targets: int = 0
    found_count: int = 0


@dataclass
class ServerResult:
    host: str
    port: int
    edition: str
    version: str = ""
    protocol: Optional[int] = None
    players_online: Optional[int] = None
    players_max: Optional[int] = None
    latency_ms: Optional[float] = None
    motd: str = ""
    favicon_present: bool = False
    discovered_at: str = field(default_factory=utc_now)
    scan_run_id: Optional[int] = None
    favorite: bool = False
    notes: str = ""

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def players_display(self) -> str:
        online = "" if self.players_online is None else str(self.players_online)
        maximum = "" if self.players_max is None else str(self.players_max)
        return f"{online}/{maximum}".strip("/")

    def to_export_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "edition": self.edition,
            "version": self.version,
            "protocol": self.protocol,
            "players_online": self.players_online,
            "players_max": self.players_max,
            "latency_ms": self.latency_ms,
            "motd": self.motd,
            "favicon_present": self.favicon_present,
            "discovered_at": self.discovered_at,
            "scan_run_id": self.scan_run_id,
            "favorite": self.favorite,
            "notes": self.notes,
        }


@dataclass
class MonitorAlert:
    event_type: str
    profile_id: Optional[int]
    current_run_id: int
    previous_run_id: Optional[int]
    host: str
    port: int
    edition: str
    before_value: str = ""
    after_value: str = ""
    created_at: str = field(default_factory=utc_now)
    acknowledged: bool = False
    id: Optional[int] = None

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def identity(self) -> str:
        return f"{self.host.lower()}:{self.port}:{self.edition.lower()}"


@dataclass
class McScansServer:
    host: str
    port: int
    edition: str = "java"
    version: str = ""
    protocol: Optional[int] = None
    players_online: Optional[int] = None
    players_max: Optional[int] = None
    latency_ms: Optional[float] = None
    motd: str = ""
    motd_normalized: str = ""
    software: str = ""
    server_type: str = ""
    auth_mode: Optional[int] = None
    is_live: Optional[bool] = None
    favicon_hash: str = ""
    timestamp: str = ""
    country: str = ""
    org: str = ""
    tags: List[str] = field(default_factory=list)

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    def to_server_result(self) -> ServerResult:
        details = []
        if self.software:
            details.append(f"software={self.software}")
        if self.server_type:
            details.append(f"type={self.server_type}")
        if self.country:
            details.append(f"country={self.country}")
        if self.org:
            details.append(f"org={self.org}")
        if self.tags:
            details.append(f"tags={','.join(self.tags)}")
        if self.timestamp:
            details.append(f"mcscans_timestamp={self.timestamp}")
        return ServerResult(
            host=self.host,
            port=self.port,
            edition=self.edition,
            version=self.version,
            protocol=self.protocol,
            players_online=self.players_online,
            players_max=self.players_max,
            latency_ms=self.latency_ms,
            motd=self.motd_normalized or self.motd,
            favicon_present=bool(self.favicon_hash),
            notes="MCScans import" + (": " + "; ".join(details) if details else ""),
        )


@dataclass
class McScansDatasetFile:
    dataset_id: str
    name: str
    size: int = 0
    lines: Optional[int] = None
    modified_at: str = ""

    @property
    def download_url(self) -> str:
        return f"https://data.mcscans.fi/{self.dataset_id}/{self.name}"


@dataclass
class McScansDataset:
    dataset_id: str
    modified_at: str = ""
    files: List[McScansDatasetFile] = field(default_factory=list)
