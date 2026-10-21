"""Kerberos for host queries (WinRM / WMI / SMB to workstations).

NTLM sent the query account's credentials to every host in the scanned subnets, where any rogue
listener could capture or relay them. With Kerberos the account only gets a service ticket for the
real computer it talks to. Kerberos needs the computer's DNS name (SPN), not its IP: IPs are turned
into FQDNs via PTR, hosts without a PTR record are skipped rather than queried over NTLM.

Mode: env HOST_QUERY_AUTH = "kerberos" (default) | "ntlm" (rollback).
"""
from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import threading
import time

from ..env_settings import get_env

_CCACHE = "/tmp/krb5cc_adportal_hostquery"  # plain path: impacket does not understand "FILE:"
_RENEW_AFTER_S = 4 * 60 * 60                # TGT lifetime on the DCs is 10 h
_lock = threading.Lock()
_state: dict = {"key": "", "ts": 0.0}


def enabled() -> bool:
    return (get_env().host_query_auth or "kerberos").strip().lower() == "kerberos"


def split_principal(username: str, domain_suffix: str) -> tuple[str, str]:
    """(user, REALM) from 'user@domain', 'DOMAIN\\user' or 'user'."""
    u = (username or "").strip()
    realm = (domain_suffix or "").strip().strip(".")
    if "@" in u:
        u, realm = u.split("@", 1)
    elif "\\" in u:
        u = u.split("\\", 1)[1]
    return u, realm.upper()


def ensure_ticket(username: str, password: str, domain_suffix: str) -> None:
    """Get (or reuse) a TGT for the query account in a private credential cache (kinit)."""
    user, realm = split_principal(username, domain_suffix)
    principal = f"{user}@{realm}"
    key = hashlib.sha256(f"{principal}\0{password}".encode()).hexdigest()
    with _lock:
        os.environ["KRB5CCNAME"] = _CCACHE
        fresh = _state["key"] == key and (time.time() - _state["ts"]) < _RENEW_AFTER_S
        if fresh and subprocess.run(["klist", "-s"], capture_output=True).returncode == 0:
            return
        r = subprocess.run(["kinit", principal], input=password + "\n", text=True, capture_output=True, timeout=20)
        if r.returncode != 0:
            _state.update(key="", ts=0.0)
            raise RuntimeError("kinit: " + ((r.stderr or r.stdout or "").strip()[:200] or "ошибка получения билета Kerberos"))
        _state.update(key=key, ts=time.time())


def kerberos_targets(targets: list[str], domain_suffix: str) -> list[str]:
    """Only FQDNs: IPs are resolved via PTR, short names get the domain suffix."""
    out: list[str] = []
    suffix = (domain_suffix or "").strip().strip(".").lower()
    for t in targets:
        t = (t or "").strip().rstrip(".")
        if not t:
            continue
        try:
            socket.inet_aton(t)
            is_ip = t.count(".") == 3
        except OSError:
            is_ip = False
        if is_ip:
            try:
                name = socket.gethostbyaddr(t)[0].rstrip(".")
            except (socket.herror, socket.gaierror, OSError):
                continue
            t = name
        if "." not in t and suffix:
            t = f"{t}.{suffix}"
        if t.lower() not in (x.lower() for x in out):
            out.append(t)
    return out
