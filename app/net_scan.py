from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from .host_logon import find_logged_on_users
from .presence import normalize_login
from .utils.numbers import clamp_int
from .utils.tcp_probe import tcp_probe_any


PROBE_PORTS = (445, 5985, 5986, 135)

# Shared executor for slow/blocking system resolver calls.
# Creating a ThreadPoolExecutor per reverse_dns() call is expensive and creates
# unnecessary threads under load.
_RDNS_EXECUTOR: concurrent.futures.ThreadPoolExecutor | None = None


def _get_rdns_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _RDNS_EXECUTOR
    if _RDNS_EXECUTOR is None:
        # Keep this small: reverse DNS fallback should not starve the main scan pool.
        _RDNS_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=8)
    return _RDNS_EXECUTOR


def quick_probe_any(host: str, timeout_ms: int = 350) -> bool:
    """Fast L4 probe to avoid slow/pointless logon checks on non-Windows/non-alive hosts."""
    ms = clamp_int(timeout_ms, default=350, min_v=50, max_v=5000)
    t = ms / 1000.0
    return tcp_probe_any(host, PROBE_PORTS, timeout_s=t)


# Backward-compatible name (some versions of tasks.py import this)
def is_windows_candidate(host: str, timeout_ms: int = 350) -> bool:
    return quick_probe_any(host, timeout_ms=timeout_ms)


def parse_cidrs(raw: str) -> list[ipaddress.IPv4Network]:
    """Parses one CIDR per line. Lines starting with # or ; are ignored."""
    out: list[ipaddress.IPv4Network] = []
    for line in (raw or "").splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("#") or s.startswith(";"):
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
        except Exception:
            continue
        if isinstance(net, ipaddress.IPv4Network):
            out.append(net)
    return out


def iter_hosts(nets: Iterable[ipaddress.IPv4Network]) -> list[str]:
    ips: list[str] = []
    for n in nets:
        for ip in n.hosts():
            ips.append(str(ip))
    return ips


# Backward-compatible alias (some versions of tasks.py import this)
def expand_hosts(nets: Iterable[ipaddress.IPv4Network]) -> list[str]:
    return iter_hosts(nets)


def _dns_server_for_ip(ip: str, nets: Iterable[ipaddress.IPv4Network]) -> str:
    """For a given IP, chooses DNS server as 'first usable' address of the matching CIDR (network + 1)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return ""

    for n in nets:
        try:
            if ip_obj in n:
                # For /31 or /32 there may be no usable +1; handle safely.
                dns_int = int(n.network_address) + 1
                dns_ip = ipaddress.ip_address(dns_int)
                # If +1 falls outside network for weird masks, ignore.
                if dns_ip in n:
                    return str(dns_ip)
                return ""
        except Exception:
            continue
    return ""


def reverse_dns_via_server(ip: str, dns_server: str, timeout_s: float = 1.0) -> str:
    """PTR lookup напрямую на заданный DNS (без системного resolv.conf контейнера)."""
    ip = (ip or "").strip()
    dns_server = (dns_server or "").strip()
    if not ip or not dns_server:
        return ""

    try:
        import dns.resolver  # type: ignore
        import dns.reversename  # type: ignore

        rev = dns.reversename.from_address(ip)
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [dns_server]
        r.timeout = float(timeout_s)
        r.lifetime = float(timeout_s)
        ans = r.resolve(rev, "PTR")
        return str(ans[0]).rstrip(".")
    except Exception:
        return ""


def reverse_dns(ip: str, *, nets: Iterable[ipaddress.IPv4Network] | None = None, timeout_s: float = 0.6) -> str:
    """
    Best-effort hostname resolution.
    1) If CIDRs are provided, tries PTR via per-subnet DNS (network+1).
    2) Fallback: socket.gethostbyaddr (system resolver), with strict timeout.
    """
    ip = (ip or "").strip()
    if not ip:
        return ""

    # First try: direct PTR via subnet DNS
    try:
        if nets:
            dns_srv = _dns_server_for_ip(ip, nets)
            if dns_srv:
                name = reverse_dns_via_server(ip, dns_srv, timeout_s=max(0.2, float(timeout_s)))
                if name:
                    return name
    except Exception:
        pass

    # Fallback: system resolver with timeout (to avoid hangs)
    def _do() -> str:
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return (host or "").strip()
        except Exception:
            return ""

    ex = _get_rdns_executor()
    fut = ex.submit(_do)
    try:
        return fut.result(timeout=max(0.2, float(timeout_s)))
    except Exception:
        return ""


def short_hostname(name: str) -> str:
    s = (name or "").strip().rstrip(".")
    if not s:
        return ""
    return s.split(".", 1)[0]


@dataclass
class ScanResult:
    total_ips: int
    probed: int
    alive: int
    queried: int
    users_found: int
    errors: int
    presence: dict[str, dict]  # login_lower -> {host, ip, method, ts} (last known location per user)
    matches: list[dict]        # [{host, ip, login, method, ts}] (per host-user pair)


# Backward-compatible alias (some versions of tasks.py import this)
HostScanResult = ScanResult


def scan_presence(
    *,
    cidrs_text: str,
    domain_suffix: str,
    query_username: str,
    query_password: str,
    per_method_timeout_s: int,
    concurrency: int = 64,
    probe_timeout_ms: int = 350,
    max_hosts: int = 20000,
) -> ScanResult:
    nets = parse_cidrs(cidrs_text)
    ips = iter_hosts(nets)

    total = len(ips)
    if total > max_hosts:
        return ScanResult(
            total_ips=total,
            probed=0,
            alive=0,
            queried=0,
            users_found=0,
            errors=1,
            presence={},
            matches=[],
        )

    conc = clamp_int(concurrency, default=64, min_v=1, max_v=256)
    per_method_timeout_s = clamp_int(per_method_timeout_s, default=60, min_v=5, max_v=300)

    presence: dict[str, dict] = {}
    probed = 0
    alive = 0
    queried = 0
    users_found = 0
    errors = 0

    now = datetime.utcnow()

    matches: list[dict] = []

    def work_safe(ip: str) -> tuple[str, list[str], str, str, bool]:
        """Returns (ip, users, method, hostname_short, is_error)."""
        try:
            if not quick_probe_any(ip, timeout_ms=probe_timeout_ms):
                return ip, [], "", "", False

            users, method, _ms, _attempts = find_logged_on_users(
                ip,
                domain_suffix=domain_suffix,
                query_username=query_username,
                query_password=query_password,
                per_method_timeout_s=per_method_timeout_s,
            )
            users = users or []
            hostname = ""
            if users:
                # IMPORTANT: use per-subnet DNS PTR (network+1) based on explicit nets.
                hostname = short_hostname(reverse_dns(ip, nets=nets, timeout_s=1.0))
            return ip, users, method or "", hostname, False
        except Exception:
            return ip, [], "", "", True

    # IMPORTANT:
    # Do NOT use executor.map here.
    # map() yields results in *input order* (head-of-line blocking): a single slow/hung host
    # at the start of a subnet can make the whole scan look "stuck" for a long time.
    # Using as_completed() allows fast hosts to be processed immediately and the scan to
    # make visible progress even with a few problematic IPs.
    with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
        futs: list[concurrent.futures.Future] = [ex.submit(work_safe, ip) for ip in ips]
        for fut in concurrent.futures.as_completed(futs):
            ip2, users, method, hostname, is_err = fut.result()
            probed += 1
            if is_err:
                errors += 1
                continue

            if users or method:
                alive += 1
            if users:
                queried += 1
                for u in users:
                    key = normalize_login(u)
                    if not key:
                        continue
                    presence[key] = {
                        "host": hostname,
                        "ip": ip2,
                        "method": method,
                        "ts": now,
                    }
                    matches.append(
                        {
                            "host": hostname,
                            "ip": ip2,
                            "login": key,
                            "method": method,
                            "ts": now,
                        }
                    )

    users_found = len(presence)

    return ScanResult(
        total_ips=total,
        probed=probed,
        alive=alive,
        queried=queried,
        users_found=users_found,
        errors=errors,
        presence=presence,
        matches=matches,
    )
