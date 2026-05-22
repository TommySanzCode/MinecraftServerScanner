from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .models import McScansDataset, McScansDatasetFile, McScansServer

API_BASE_URL = "https://api.mcscans.fi/public/v1"
DATASET_API_URL = "https://data.mcscans.fi/api/"
DEFAULT_PAGE_SIZE = 20


@dataclass
class McScansSearchResult:
    servers: List[McScansServer]
    total_servers: Optional[int] = None
    page: int = 1
    page_size: int = DEFAULT_PAGE_SIZE
    next_cursor: Optional[str] = None
    has_more: bool = False
    raw_keys: List[str] = field(default_factory=list)


class McScansClient:
    def __init__(self, api_base_url: str = API_BASE_URL, dataset_api_url: str = DATASET_API_URL, timeout: float = 20.0):
        self.api_base_url = api_base_url.rstrip("/")
        self.dataset_api_url = dataset_api_url
        self.timeout = timeout

    def search_servers(
        self,
        *,
        query: str = "",
        edition: str = "Java",
        software: str = "",
        version: str = "",
        source: str = "",
        sort: str = "",
        auth_mode: str = "",
        live: Optional[bool] = None,
        page: int = 1,
        cursor: str = "",
    ) -> McScansSearchResult:
        page = max(1, int(page))
        params: Dict[str, Any] = {}
        if query:
            params["query"] = query
        if edition and edition != "Any":
            params["edition"] = edition
        if software:
            params["software"] = software
        if version:
            params["version"] = version
        if source:
            params["source"] = source
        if sort:
            params["sort"] = sort
        if auth_mode:
            params["authMode"] = auth_mode
        if live is not None:
            params["live"] = "true" if live else "false"
        if cursor:
            params["cursor"] = cursor
        else:
            params["page"] = page

        payload = self._get_json(f"{self.api_base_url}/servers?{urlencode(params)}")
        records = _extract_servers(payload)
        inferred_edition = (edition or "Java").lower()
        if inferred_edition == "any":
            inferred_edition = "java"
        return McScansSearchResult(
            servers=[server_from_record(record, inferred_edition) for record in records],
            total_servers=_safe_int(payload.get("totalServers") or payload.get("total") or payload.get("count")),
            page=page,
            page_size=DEFAULT_PAGE_SIZE,
            next_cursor=payload.get("nextCursor") or payload.get("next_cursor"),
            has_more=bool(payload.get("hasMore") or payload.get("has_more")),
            raw_keys=sorted(payload.keys()),
        )

    def list_datasets(self) -> List[McScansDataset]:
        payload = self._get_json(self.dataset_api_url)
        datasets: List[McScansDataset] = []
        for entry in payload.get("files", []):
            if entry.get("type") != "directory":
                continue
            dataset_id = str(entry.get("name", ""))
            files = []
            for child in entry.get("children", []) or []:
                if child.get("type") != "file":
                    continue
                files.append(
                    McScansDatasetFile(
                        dataset_id=dataset_id,
                        name=str(child.get("name", "")),
                        size=_safe_int(child.get("size")) or 0,
                        lines=_safe_int(child.get("lines")),
                        modified_at=str(child.get("mtime", "")),
                    )
                )
            datasets.append(
                McScansDataset(
                    dataset_id=dataset_id,
                    modified_at=str(entry.get("mtime", "")),
                    files=files,
                )
            )
        return datasets

    def _get_json(self, url: str) -> Dict[str, Any]:
        request = Request(url, headers={"Accept": "application/json", "User-Agent": "MinecraftServerScanner/2.2"})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
        except HTTPError as exc:
            retry = exc.headers.get("Retry-After") if exc.headers else None
            suffix = f" Retry after {retry} seconds." if retry else ""
            raise RuntimeError(f"MCScans request failed with HTTP {exc.code}.{suffix}") from exc
        except URLError as exc:
            raise RuntimeError(f"MCScans request failed: {exc.reason}") from exc
        return json.loads(body)


def server_from_record(record: Dict[str, Any], default_edition: str = "java") -> McScansServer:
    player_stats = record.get("playerStats") or {}
    ping = record.get("ping") or {}
    favicon = record.get("favicon") or {}
    geolocation = record.get("geolocation") or record.get("geo") or {}
    edition = str(record.get("edition") or default_edition or "java").lower()
    if edition == "java edition":
        edition = "java"
    if edition == "bedrock edition":
        edition = "bedrock"
    return McScansServer(
        host=str(record.get("hostname") or record.get("host") or record.get("ip") or ""),
        port=_safe_int(record.get("port")) or 25565,
        edition=edition,
        version=str(record.get("version") or ""),
        protocol=_safe_int(ping.get("protocol")),
        players_online=_safe_int(player_stats.get("onlinePlayers")),
        players_max=_safe_int(player_stats.get("maxPlayers")),
        latency_ms=_safe_float(ping.get("latency")),
        motd=str(record.get("motd") or ""),
        motd_normalized=str(record.get("motd_normalized") or ""),
        software=str(record.get("software") or ""),
        server_type=str(record.get("serverType") or ""),
        auth_mode=_safe_int(record.get("authMode")),
        is_live=record.get("is_live") if isinstance(record.get("is_live"), bool) else None,
        favicon_hash=str(favicon.get("hash") or ""),
        timestamp=str(record.get("timestamp") or record.get("updated_at") or ""),
        country=str(geolocation.get("country") or ""),
        org=str(geolocation.get("org") or ""),
        tags=[str(tag) for tag in (record.get("tags") or [])],
    )


def dataset_target_files(datasets: List[McScansDataset]) -> List[McScansDatasetFile]:
    files: List[McScansDatasetFile] = []
    for dataset in datasets:
        for file in dataset.files:
            if "zmap" in file.name.lower() and file.name.lower().endswith((".csv", ".csv.gz")):
                files.append(file)
    return files


def _extract_servers(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    if isinstance(payload.get("servers"), list):
        return payload["servers"]
    data = payload.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("servers"), list):
        return data["servers"]
    return []


def _safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None
