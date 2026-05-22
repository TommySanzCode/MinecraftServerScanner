from __future__ import annotations

from typing import Iterable, List, Optional, Set

from .models import MonitorAlert, ServerResult

LATENCY_CHANGE_THRESHOLD_MS = 100.0


def server_identity(result: ServerResult) -> str:
    return f"{result.host.lower()}:{result.port}:{result.edition.lower()}"


def result_summary(result: ServerResult) -> str:
    latency = "" if result.latency_ms is None else f", {result.latency_ms:.1f} ms"
    version = result.version or "unknown version"
    players = result.players_display or "unknown players"
    return f"{version}, {players}{latency}"


def compare_results(
    previous: Iterable[ServerResult],
    current: Iterable[ServerResult],
    *,
    profile_id: Optional[int] = None,
    previous_run_id: Optional[int] = None,
    current_run_id: int,
    known_identities: Optional[Set[str]] = None,
    latency_threshold_ms: float = LATENCY_CHANGE_THRESHOLD_MS,
) -> List[MonitorAlert]:
    previous_by_id = {server_identity(result): result for result in previous}
    current_by_id = {server_identity(result): result for result in current}
    known_identities = known_identities or set()
    alerts: List[MonitorAlert] = []

    for identity in sorted(current_by_id.keys() - previous_by_id.keys()):
        result = current_by_id[identity]
        event_type = "online" if identity in known_identities else "new"
        alerts.append(
            _alert(
                event_type,
                result,
                profile_id,
                previous_run_id,
                current_run_id,
                before_value="",
                after_value=result_summary(result),
            )
        )

    for identity in sorted(previous_by_id.keys() - current_by_id.keys()):
        result = previous_by_id[identity]
        alerts.append(
            _alert(
                "offline",
                result,
                profile_id,
                previous_run_id,
                current_run_id,
                before_value=result_summary(result),
                after_value="",
            )
        )

    for identity in sorted(previous_by_id.keys() & current_by_id.keys()):
        before = previous_by_id[identity]
        after = current_by_id[identity]
        alerts.extend(
            _changed_alerts(before, after, profile_id, previous_run_id, current_run_id, latency_threshold_ms)
        )

    return alerts


def alerts_for_monitor_cycle(
    previous: Iterable[ServerResult],
    current: Iterable[ServerResult],
    *,
    profile_id: Optional[int],
    previous_run_id: Optional[int],
    current_run_id: int,
    known_identities: Optional[Set[str]] = None,
) -> List[MonitorAlert]:
    if previous_run_id is None:
        return []
    return compare_results(
        previous,
        current,
        profile_id=profile_id,
        previous_run_id=previous_run_id,
        current_run_id=current_run_id,
        known_identities=known_identities,
    )


def identities_for(results: Iterable[ServerResult]) -> Set[str]:
    return {server_identity(result) for result in results}


def _changed_alerts(
    before: ServerResult,
    after: ServerResult,
    profile_id: Optional[int],
    previous_run_id: Optional[int],
    current_run_id: int,
    latency_threshold_ms: float,
) -> List[MonitorAlert]:
    alerts: List[MonitorAlert] = []
    if before.version != after.version:
        alerts.append(_alert("version_changed", after, profile_id, previous_run_id, current_run_id, before.version, after.version))
    if before.motd != after.motd:
        alerts.append(_alert("motd_changed", after, profile_id, previous_run_id, current_run_id, before.motd, after.motd))
    if (before.players_online, before.players_max) != (after.players_online, after.players_max):
        alerts.append(
            _alert(
                "players_changed",
                after,
                profile_id,
                previous_run_id,
                current_run_id,
                before.players_display,
                after.players_display,
            )
        )
    if before.latency_ms is not None and after.latency_ms is not None:
        if abs(after.latency_ms - before.latency_ms) >= latency_threshold_ms:
            alerts.append(
                _alert(
                    "latency_changed",
                    after,
                    profile_id,
                    previous_run_id,
                    current_run_id,
                    f"{before.latency_ms:.1f} ms",
                    f"{after.latency_ms:.1f} ms",
                )
            )
    return alerts


def _alert(
    event_type: str,
    result: ServerResult,
    profile_id: Optional[int],
    previous_run_id: Optional[int],
    current_run_id: int,
    before_value: str,
    after_value: str,
) -> MonitorAlert:
    return MonitorAlert(
        event_type=event_type,
        profile_id=profile_id,
        previous_run_id=previous_run_id,
        current_run_id=current_run_id,
        host=result.host,
        port=result.port,
        edition=result.edition,
        before_value=before_value or "",
        after_value=after_value or "",
    )

