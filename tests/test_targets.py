from pathlib import Path

import pytest

from minecraft_server_scanner.models import ScanSettings
from minecraft_server_scanner.targets import (
    contains_public_targets,
    count_targets,
    iter_targets,
    parse_ports,
    validate_scan_settings,
)


def test_parse_ports_supports_lists_and_ranges():
    assert parse_ports("25565,19132-19133,25565") == [19132, 19133, 25565]


def test_parse_ports_rejects_invalid_values():
    with pytest.raises(ValueError):
        parse_ports("0,70000")


def test_iter_targets_supports_single_range_cidr_and_files(tmp_path: Path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text("play.example.net\n# ignored\n192.168.1.8\n", encoding="utf-8")

    assert list(iter_targets("192.168.1.1")) == ["192.168.1.1"]
    assert list(iter_targets("192.168.1.1-192.168.1.3")) == [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
    ]
    assert list(iter_targets("192.168.1.0/30")) == ["192.168.1.1", "192.168.1.2"]
    assert list(iter_targets(f"@{target_file}")) == ["play.example.net", "192.168.1.8"]


def test_count_targets_and_public_detection():
    assert count_targets("192.168.1.0/30") == 2
    assert contains_public_targets("8.8.8.8")
    assert not contains_public_targets("192.168.1.1-192.168.1.20")


def test_validate_scan_settings():
    validate_scan_settings(ScanSettings(target_spec="127.0.0.1", ports="25565", edition="java"))
    with pytest.raises(ValueError):
        validate_scan_settings(ScanSettings(target_spec="", ports="25565", edition="java"))

