from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Iterable, Iterator, List, Sequence, Set

from .models import ScanSettings


PRIVATE_TARGET_WARNING = (
    "This scan includes public/non-private IP ranges. Only scan networks you own "
    "or have permission to test."
)


def edition_values(edition: str) -> List[str]:
    value = edition.lower().strip()
    if value == "both":
        return ["java", "bedrock"]
    if value in {"java", "bedrock"}:
        return [value]
    raise ValueError("Edition must be java, bedrock, or both.")


def parse_ports(spec: str) -> List[int]:
    if not spec or not spec.strip():
        raise ValueError("Enter at least one port.")

    ports: Set[int] = set()
    for token in spec.replace("\n", ",").split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            start = _parse_port_number(start_text)
            end = _parse_port_number(end_text)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_port_number(token))

    if not ports:
        raise ValueError("Enter at least one valid port.")
    return sorted(ports)


def _parse_port_number(value: str) -> int:
    try:
        port = int(value.strip())
    except ValueError:
        raise ValueError(f"Invalid port: {value.strip()}") from None
    if port < 1 or port > 65535:
        raise ValueError(f"Port out of range: {port}")
    return port


def iter_targets(spec: str) -> Iterator[str]:
    tokens = _target_tokens(spec)
    if not tokens:
        raise ValueError("Enter at least one target.")
    for token in tokens:
        yield from _iter_target_token(token)


def count_targets(spec: str) -> int:
    count = 0
    for token in _target_tokens(spec):
        count += _count_target_token(token)
    if count == 0:
        raise ValueError("Enter at least one target.")
    return count


def contains_public_targets(spec: str) -> bool:
    for token in _target_tokens(spec):
        if _token_contains_public_target(token):
            return True
    return False


def validate_scan_settings(settings: ScanSettings) -> None:
    count_targets(settings.target_spec)
    parse_ports(settings.ports)
    edition_values(settings.edition)
    if settings.timeout <= 0:
        raise ValueError("Timeout must be greater than 0 seconds.")
    if settings.concurrency < 1 or settings.concurrency > 512:
        raise ValueError("Concurrency must be between 1 and 512.")
    if settings.retries < 0 or settings.retries > 10:
        raise ValueError("Retries must be between 0 and 10.")
    if settings.min_players < 0:
        raise ValueError("Minimum players cannot be negative.")


def _target_tokens(spec: str) -> List[str]:
    tokens: List[str] = []
    for raw in spec.replace(",", "\n").splitlines():
        token = raw.strip()
        if not token or token.startswith("#"):
            continue
        if token.startswith("@"):
            tokens.extend(_read_target_file(Path(token[1:].strip())))
        elif token.lower().startswith("file:"):
            tokens.extend(_read_target_file(Path(token.split(":", 1)[1].strip())))
        else:
            tokens.append(token)
    return tokens


def _read_target_file(path: Path) -> List[str]:
    if not path.exists():
        raise ValueError(f"Target file does not exist: {path}")
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _iter_target_token(token: str) -> Iterator[str]:
    if "/" in token:
        network = ipaddress.ip_network(token, strict=False)
        if network.num_addresses == 1:
            yield str(network.network_address)
        else:
            for ip in network.hosts():
                yield str(ip)
        return

    if "-" in token and _looks_like_ip_range(token):
        start_text, end_text = token.split("-", 1)
        start = ipaddress.ip_address(start_text.strip())
        end = ipaddress.ip_address(end_text.strip())
        if start.version != end.version:
            raise ValueError("IP range start/end versions must match.")
        if int(end) < int(start):
            raise ValueError("IP range end cannot be before start.")
        current = int(start)
        while current <= int(end):
            yield str(ipaddress.ip_address(current))
            current += 1
        return

    _validate_single_target(token)
    yield token


def _count_target_token(token: str) -> int:
    if "/" in token:
        network = ipaddress.ip_network(token, strict=False)
        if network.num_addresses == 1:
            return 1
        if network.version == 4 and network.num_addresses > 2:
            return int(network.num_addresses) - 2
        return int(network.num_addresses)
    if "-" in token and _looks_like_ip_range(token):
        start_text, end_text = token.split("-", 1)
        start = ipaddress.ip_address(start_text.strip())
        end = ipaddress.ip_address(end_text.strip())
        if start.version != end.version:
            raise ValueError("IP range start/end versions must match.")
        if int(end) < int(start):
            raise ValueError("IP range end cannot be before start.")
        return int(end) - int(start) + 1
    _validate_single_target(token)
    return 1


def _token_contains_public_target(token: str) -> bool:
    try:
        if "/" in token:
            network = ipaddress.ip_network(token, strict=False)
            return not network.is_private
        if "-" in token and _looks_like_ip_range(token):
            start_text, end_text = token.split("-", 1)
            start = ipaddress.ip_address(start_text.strip())
            end = ipaddress.ip_address(end_text.strip())
            return not start.is_private or not end.is_private
        ip = ipaddress.ip_address(token)
        return not ip.is_private
    except ValueError:
        return False


def _looks_like_ip_range(token: str) -> bool:
    parts = token.split("-", 1)
    if len(parts) != 2:
        return False
    try:
        ipaddress.ip_address(parts[0].strip())
        ipaddress.ip_address(parts[1].strip())
        return True
    except ValueError:
        return False


def _validate_single_target(token: str) -> None:
    if not token:
        raise ValueError("Target cannot be blank.")
    if any(ch.isspace() for ch in token):
        raise ValueError(f"Invalid target: {token}")
    if token.startswith("-") or token.endswith("-"):
        raise ValueError(f"Invalid target: {token}")
