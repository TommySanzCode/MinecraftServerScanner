import threading

from minecraft_server_scanner.models import ScanSettings, ServerResult
from minecraft_server_scanner.scanner import ScanEngine


class FakeClient:
    def __init__(self):
        self.calls = []
        self.fail_once = True

    def query(self, host, port, edition, timeout):
        self.calls.append((host, port, edition, timeout))
        if port == 1:
            raise TimeoutError("closed")
        if port == 2 and self.fail_once:
            self.fail_once = False
            raise TimeoutError("temporary")
        return ServerResult(
            host=host,
            port=port,
            edition=edition,
            version="1.20.4",
            players_online=1,
            players_max=20,
            latency_ms=10.0,
        )


def test_scan_engine_success_and_retry():
    settings = ScanSettings(target_spec="127.0.0.1", ports="2", edition="java", retries=1, concurrency=1)
    client = FakeClient()
    results = []

    summary = ScanEngine(settings, query_client=client).scan(result_callback=results.append)

    assert summary.found_count == 1
    assert len(client.calls) == 2
    assert results[0].host == "127.0.0.1"


def test_scan_engine_reports_closed_ports():
    settings = ScanSettings(target_spec="127.0.0.1", ports="1", edition="java", retries=0, concurrency=1)
    logs = []

    summary = ScanEngine(settings, query_client=FakeClient()).scan(log_callback=logs.append)

    assert summary.completed_targets == 1
    assert summary.found_count == 0
    assert "MISS java 127.0.0.1:1" in logs[0]


def test_scan_engine_cancellation():
    settings = ScanSettings(
        target_spec="127.0.0.1-127.0.0.3",
        ports="25565",
        edition="java",
        concurrency=1,
    )
    cancel_event = threading.Event()

    def on_progress(done, total, found):
        if done == 1:
            cancel_event.set()

    summary = ScanEngine(settings, query_client=FakeClient()).scan(
        progress_callback=on_progress,
        cancel_event=cancel_event,
    )

    assert summary.cancelled is True
    assert summary.completed_targets < summary.total_targets

