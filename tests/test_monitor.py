from minecraft_server_scanner.models import ServerResult
from minecraft_server_scanner.monitor import alerts_for_monitor_cycle, compare_results, server_identity


def result(
    host="127.0.0.1",
    port=25565,
    edition="java",
    version="1.20.4",
    players_online=1,
    players_max=20,
    latency_ms=20.0,
    motd="hello",
):
    return ServerResult(
        host=host,
        port=port,
        edition=edition,
        version=version,
        players_online=players_online,
        players_max=players_max,
        latency_ms=latency_ms,
        motd=motd,
    )


def test_first_monitor_run_creates_no_alerts():
    alerts = alerts_for_monitor_cycle(
        [],
        [result()],
        profile_id=1,
        previous_run_id=None,
        current_run_id=2,
        known_identities=set(),
    )

    assert alerts == []


def test_compare_detects_new_offline_online_and_core_changes():
    previous = [
        result(host="127.0.0.1", version="1.20.4", players_online=1, latency_ms=20.0, motd="old"),
        result(host="127.0.0.2"),
    ]
    reappearing = result(host="127.0.0.3")
    current = [
        result(host="127.0.0.1", version="1.20.5", players_online=4, latency_ms=140.0, motd="new"),
        reappearing,
        result(host="127.0.0.4"),
    ]
    known = {server_identity(previous[0]), server_identity(previous[1]), server_identity(reappearing)}

    alerts = compare_results(
        previous,
        current,
        profile_id=1,
        previous_run_id=10,
        current_run_id=11,
        known_identities=known,
    )
    event_types = [alert.event_type for alert in alerts]

    assert "offline" in event_types
    assert "online" in event_types
    assert "new" in event_types
    assert "version_changed" in event_types
    assert "motd_changed" in event_types
    assert "players_changed" in event_types
    assert "latency_changed" in event_types


def test_latency_changes_below_threshold_do_not_alert():
    alerts = compare_results(
        [result(latency_ms=20.0)],
        [result(latency_ms=119.0)],
        profile_id=1,
        previous_run_id=1,
        current_run_id=2,
    )

    assert "latency_changed" not in [alert.event_type for alert in alerts]
