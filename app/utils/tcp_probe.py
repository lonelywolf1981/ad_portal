from __future__ import annotations

import socket
from typing import Iterable


def tcp_probe(host: str, port: int, timeout_s: float) -> bool:
    """Fast TCP connect probe (best-effort)."""
    try:
        with socket.create_connection((host, int(port)), timeout=float(timeout_s)):
            return True
    except Exception:
        return False


def tcp_probe_any(host: str, ports: Iterable[int], timeout_s: float) -> bool:
    """Probe host against a list of ports; returns True on the first open port."""
    for p in ports:
        if tcp_probe(host, int(p), timeout_s):
            return True
    return False
