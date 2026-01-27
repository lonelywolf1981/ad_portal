from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass


@dataclass
class HostScanResult:
    ip: str
    hostname: str
    method: str
    users: list[str]  # already normalized keys
    error: str = ""


def parse_cidrs(raw: str) -> list[ipaddress.IPv4Network]:
    """Parse newline-separated CIDR list."""
    out: list[ipaddress.IPv4Network] = []
    for line in (raw or "").splitlines():
        l = line.strip()
        if not l:
            continue
        if l.startswith("#") or l.startswith(";"):
            continue

        # allow inline comments ("10.0.0.0/24  # office")
        if "#" in l:
            l = l.split("#", 1)[0].strip()
        if not l:
            continue

        try:
            net = ipaddress.ip_network(l, strict=False)
        except Exception:
            continue
        if isinstance(net, ipaddress.IPv4Network):
            out.append(net)
    # Dedupe
    uniq: dict[str, ipaddress.IPv4Network] = {str(n): n for n in out}
    return list(uniq.values())


def expand_hosts(cidrs: list[ipaddress.IPv4Network], limit: int = 10000) -> list[str]:
    ips: list[str] = []
    for n in cidrs:
        for ip in n.hosts():
            ips.append(str(ip))
            if len(ips) >= limit:
                return ips
    return ips


def tcp_probe(host: str, port: int, timeout_s: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except Exception:
        return False


def is_windows_candidate(ip: str, probe_timeout_s: float) -> bool:
    """Fast probe: try typical Windows management ports.

    This is only a heuristic to avoid expensive calls on obviously irrelevant hosts.
    """
    # Try SMB first (fast in AD LAN), then WinRM, then RPC.
    for port in (445, 5985, 5986, 135):
        if tcp_probe(ip, port, probe_timeout_s):
            return True
    return False


def reverse_dns(ip: str) -> str:
    try:
        name, _aliases, _addrs = socket.gethostbyaddr(ip)
        return (name or "").rstrip(".")
    except Exception:
        return ""
