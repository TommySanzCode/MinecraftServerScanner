from __future__ import annotations

import ipaddress
import socket
import threading
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Optional, Set, Tuple

from mcstatus import BedrockServer, JavaServer

from .models import ScanSettings, ServerResult
from .targets import count_targets, edition_values, iter_targets, parse_ports, validate_scan_settings

ProgressCallback = Callable[[int, int, int], None]
ResultCallback = Callable[[ServerResult], None]
LogCallback = Callable[[str], None]


@dataclass
class ScanSummary:
    total_targets: int
    completed_targets: int
    found_count: int
    cancelled: bool = False


class McstatusQueryClient:
    def query(self, host: str, port: int, edition: str, timeout: float) -> ServerResult:
        if edition == "java":
            return self._query_java(host, port, timeout)
        if edition == "bedrock":
            return self._query_bedrock(host, port, timeout)
        raise ValueError(f"Unsupported edition: {edition}")

    def _query_java(self, host: str, port: int, timeout: float) -> ServerResult:
        if _is_ipv4_address(host) and not _tcp_open(host, port, timeout):
            raise TimeoutError("TCP port is closed or filtered.")

        server = JavaServer.lookup(f"{host}:{port}", timeout=timeout)
        status = server.status()
        return ServerResult(
            host=host,
            port=port,
            edition="java",
            version=_safe_str(getattr(status.version, "name", "")),
            protocol=_safe_int(getattr(status.version, "protocol", None)),
            players_online=_safe_int(getattr(status.players, "online", None)),
            players_max=_safe_int(getattr(status.players, "max", None)),
            latency_ms=_safe_float(getattr(status, "latency", None)),
            motd=_motd_text(status),
            favicon_present=bool(getattr(status, "icon", None) or getattr(status, "favicon", None)),
        )

    def _query_bedrock(self, host: str, port: int, timeout: float) -> ServerResult:
        server = BedrockServer.lookup(f"{host}:{port}", timeout=timeout)
        status = server.status()
        return ServerResult(
            host=host,
            port=port,
            edition="bedrock",
            version=_safe_str(getattr(status.version, "name", "")),
            protocol=_safe_int(getattr(status.version, "protocol", None)),
            players_online=_safe_int(getattr(status.players, "online", None)),
            players_max=_safe_int(getattr(status.players, "max", None)),
            latency_ms=_safe_float(getattr(status, "latency", None)),
            motd=_motd_text(status),
            favicon_present=False,
        )


class ScanEngine:
    def __init__(self, settings: ScanSettings, query_client: Optional[McstatusQueryClient] = None):
        self.settings = settings
        self.query_client = query_client or McstatusQueryClient()

    def total_jobs(self) -> int:
        return (
            count_targets(self.settings.target_spec)
            * len(parse_ports(self.settings.ports))
            * len(edition_values(self.settings.edition))
        )

    def jobs(self) -> Iterator[Tuple[str, int, str]]:
        ports = parse_ports(self.settings.ports)
        editions = edition_values(self.settings.edition)
        for host in iter_targets(self.settings.target_spec):
            for port in ports:
                for edition in editions:
                    yield host, port, edition

    def scan(
        self,
        progress_callback: Optional[ProgressCallback] = None,
        result_callback: Optional[ResultCallback] = None,
        log_callback: Optional[LogCallback] = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> ScanSummary:
        validate_scan_settings(self.settings)
        cancel_event = cancel_event or threading.Event()
        total = self.total_jobs()
        completed = 0
        found = 0
        pending: Set[Future] = set()
        job_iter = self.jobs()
        max_pending = max(1, min(self.settings.concurrency * 2, 1024))

        def submit_more(executor: ThreadPoolExecutor) -> None:
            while not cancel_event.is_set() and len(pending) < max_pending:
                try:
                    job = next(job_iter)
                except StopIteration:
                    return
                pending.add(executor.submit(self._attempt_job, job))

        with ThreadPoolExecutor(max_workers=max(1, self.settings.concurrency)) as executor:
            submit_more(executor)
            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    completed += 1
                    result, error = future.result()
                    if result is not None:
                        found += 1
                        if result_callback:
                            result_callback(result)
                        if log_callback:
                            log_callback(f"FOUND {result.edition} {result.address} {result.version}")
                    elif error and log_callback:
                        log_callback(error)
                    if progress_callback:
                        progress_callback(completed, total, found)
                if cancel_event.is_set():
                    for future in pending:
                        future.cancel()
                    break
                submit_more(executor)

        return ScanSummary(
            total_targets=total,
            completed_targets=completed,
            found_count=found,
            cancelled=cancel_event.is_set(),
        )

    def _attempt_job(self, job: Tuple[str, int, str]) -> Tuple[Optional[ServerResult], Optional[str]]:
        host, port, edition = job
        attempts = self.settings.retries + 1
        last_error: Optional[Exception] = None
        for _ in range(attempts):
            try:
                result = self.query_client.query(host, port, edition, self.settings.timeout)
                return result, None
            except Exception as exc:  # Network probes need to tolerate many failures.
                last_error = exc
        return None, f"MISS {edition} {host}:{port} - {type(last_error).__name__}: {last_error}"


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def _is_ipv4_address(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def _safe_int(value: object) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: object) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_str(value: object) -> str:
    return "" if value is None else str(value)


def _motd_text(status: object) -> str:
    motd = getattr(status, "motd", None)
    if motd is not None and hasattr(motd, "to_plain"):
        return str(motd.to_plain())
    description = getattr(status, "description", None)
    if isinstance(description, dict):
        return str(description.get("text", description))
    if description is not None:
        return str(description)
    return ""

