from __future__ import annotations

import concurrent.futures
import re
import socket
import time
from dataclasses import dataclass


_RE_IPv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _is_ipv4(s: str) -> bool:
    s = (s or "").strip()
    if not _RE_IPv4.match(s):
        return False
    try:
        parts = [int(x) for x in s.split(".")]
        return len(parts) == 4 and all(0 <= p <= 255 for p in parts)
    except Exception:
        return False


def _tcp_probe(host: str, port: int, timeout_s: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except Exception:
        return False


def _normalize_targets(raw: str, domain_suffix: str) -> list[str]:
    raw = (raw or "").strip()
    if not raw:
        return []

    if _is_ipv4(raw):
        return [raw]

    # Already FQDN
    if "." in raw:
        return [raw]

    domain_suffix = (domain_suffix or "").strip().lstrip(".")
    if domain_suffix:
        # Try FQDN first, then short
        return [f"{raw}.{domain_suffix}", raw]
    return [raw]


def _dedupe_users(users: list[str]) -> list[str]:
    seen = set()
    out: list[str] = []
    for u in users:
        uu = (u or "").strip()
        if not uu:
            continue
        key = uu.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(uu)
    return out


def _guess_netbios(domain_suffix: str) -> str:
    d = (domain_suffix or "").strip()
    if not d:
        return ""
    return d.split(".")[0].upper()


def _split_credential(username: str, domain_suffix: str) -> tuple[str, str, str]:
    """Return (winrm_user, smb_domain, smb_user)."""
    u = (username or "").strip()
    if not u:
        return "", "", ""

    if "\\" in u:
        dom, usr = u.split("\\", 1)
        dom = dom.strip()
        usr = usr.strip()
        if dom and usr:
            return f"{dom}\\{usr}", dom, usr
        return u, dom, usr

    if "@" in u:
        # UPN
        return u, "", u

    # Plain username: guess NETBIOS from domain
    netbios = _guess_netbios(domain_suffix)
    if netbios:
        return f"{netbios}\\{u}", netbios, u
    return u, "", u


@dataclass
class Attempt:
    method: str
    status: str  # ok | empty | timeout | error | skipped
    message: str
    elapsed_ms: int
    users: list[str]


def _winrm_query_users(target: str, username: str, password: str, per_method_timeout_s: int) -> list[str]:
    """WinRM: try `quser`, fallback to Win32_ComputerSystem.UserName."""
    import winrm  # type: ignore

    endpoints: list[str] = []
    # Quick probes to avoid long hangs
    if _tcp_probe(target, 5985, timeout_s=2.0):
        endpoints.append(f"http://{target}:5985/wsman")
    if _tcp_probe(target, 5986, timeout_s=2.0):
        endpoints.append(f"https://{target}:5986/wsman")

    if not endpoints:
        raise RuntimeError("WinRM порты 5985/5986 недоступны")

    # Keep winrm internal timeouts comfortably below per_method_timeout_s
    op_timeout = max(10, min(30, per_method_timeout_s - 10))
    read_timeout = max(op_timeout + 5, min(per_method_timeout_s - 2, op_timeout + 15))

    ps = r"""
$users = @()

try { $q = (quser 2>$null) } catch { $q = $null }

if ($q) {
  $lines = $q | Select-Object -Skip 1
  foreach ($l in $lines) {
    $l = ($l -as [string]).Trim()
    if (-not $l) { continue }
    $parts = $l -split '\s+'
    if ($parts.Count -gt 0) {
      $u = $parts[0].Trim('>')
      if ($u) { $users += $u }
    }
  }
}

if (-not $users -or $users.Count -eq 0) {
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs -and $cs.UserName) { $users += $cs.UserName }
  } catch {}
}

$users | Sort-Object -Unique
"""

    last_err: Exception | None = None
    for ep in endpoints:
        try:
            sess = winrm.Session(
                ep,
                auth=(username, password),
                transport="ntlm",
                server_cert_validation="ignore",
                read_timeout_sec=read_timeout,
                operation_timeout_sec=op_timeout,
            )
            r = sess.run_ps(ps)
            if r.status_code != 0:
                err = (r.std_err or b"").decode("utf-8", errors="replace")[:400]
                raise RuntimeError(err or "Команда завершилась с ошибкой")
            out = (r.std_out or b"").decode("utf-8", errors="replace")
            users = [x.strip() for x in out.splitlines() if x.strip()]
            return _dedupe_users(users)
        except Exception as e:
            last_err = e
            continue

    raise RuntimeError(str(last_err) if last_err else "WinRM ошибка")


def _wmi_query_user(target: str, domain: str, username: str, password: str) -> list[str]:
    """WMI/DCOM: query Win32_ComputerSystem.UserName."""
    if not _tcp_probe(target, 135, timeout_s=2.0):
        raise RuntimeError("WMI/RPC порт 135 недоступен")

    from impacket.dcerpc.v5.dcomrt import DCOMConnection  # type: ignore
    from impacket.dcerpc.v5.dcom import wmi  # type: ignore
    from impacket.dcerpc.v5.dtypes import NULL  # type: ignore

    dcom = None
    try:
        # DCOMConnection uses sockets; rely on system socket timeouts + port probe
        dcom = DCOMConnection(
            target,
            username,
            password,
            domain,
            "",
            "",
            oxidResolver=True,
            doKerberos=False,
        )
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin(r"//./root/cimv2", NULL, NULL)
        iWbemLevel1Login.RemRelease()

        query = "SELECT UserName FROM Win32_ComputerSystem"
        iEnum = iWbemServices.ExecQuery("WQL", query)

        users: list[str] = []
        while True:
            try:
                item = iEnum.Next(0xFFFFFFFF, 1)[0]
            except Exception:
                break
            try:
                props = item.getProperties()
                v = props.get("UserName", {}).get("value")
                if v:
                    users.append(str(v))
            except Exception:
                pass

        return _dedupe_users(users)
    finally:
        try:
            if dcom is not None:
                dcom.disconnect()
        except Exception:
            pass


def _smb_query_users(target: str, domain: str, username: str, password: str) -> list[str]:
    """SMB/RPC: wkssvc (interactive users) then srvsvc (network sessions)."""
    from impacket.smbconnection import SMBConnection  # type: ignore
    from impacket.dcerpc.v5 import transport, wkst, srvsvc  # type: ignore
    from impacket.dcerpc.v5.rpcrt import DCERPCException  # type: ignore

    if not _tcp_probe(target, 445, timeout_s=2.0):
        raise RuntimeError("SMB порт 445 недоступен")

    smb = SMBConnection(remoteName=target, remoteHost=target, sess_port=445, timeout=7)
    smb.login(username, password, domain)

    users: list[str] = []

    # 1) wkssvc: NetrWkstaUserEnum
    try:
        rpctransport = transport.SMBTransport(
            target,
            target,
            r"\wkssvc",
            username,
            password,
            domain,
            smb_connection=smb,
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(wkst.MSRPC_UUID_WKST)
        resp = wkst.hNetrWkstaUserEnum(dce, 1)
        dce.disconnect()

        buf = resp.get("UserInfo", {}).get("WkstaUserInfo", {}).get("Level1", {}).get("Buffer", [])
        for e in buf or []:
            try:
                u = (e.get("wkui1_username") or "").strip()
                d = (e.get("wkui1_logon_domain") or "").strip()
                if u and d:
                    users.append(f"{d}\\{u}")
                elif u:
                    users.append(u)
            except Exception:
                continue
    except DCERPCException:
        pass

    # 2) srvsvc: NetrSessionEnum
    if not users:
        try:
            rpctransport = transport.SMBTransport(
                target,
                target,
                r"\srvsvc",
                username,
                password,
                domain,
                smb_connection=smb,
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvsvc.MSRPC_UUID_SRVS)
            resp = srvsvc.hNetrSessionEnum(dce, "\\\\" + target, None, 10, 0xFFFFFFFF, 0, 0)
            dce.disconnect()

            sess = resp.get("InfoStruct", {}).get("SessionInfo", {}).get("Level10", {}).get("Buffer", [])
            for s in sess or []:
                try:
                    u = (s.get("sesi10_username") or "").strip()
                    if u:
                        users.append(u)
                except Exception:
                    continue
        except DCERPCException:
            pass

    try:
        smb.logoff()
    except Exception:
        pass

    return _dedupe_users(users)


def _run_with_timeout(fn, timeout_s: int):
    """Run in a worker thread and enforce timeout without waiting on shutdown."""
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(fn)
    try:
        return fut.result(timeout=timeout_s)
    finally:
        # Important: do NOT wait here; otherwise timeouts are ineffective.
        ex.shutdown(wait=False, cancel_futures=True)


def find_logged_on_users(
    raw_target: str,
    domain_suffix: str,
    query_username: str,
    query_password: str,
    per_method_timeout_s: int = 60,
) -> tuple[list[str], str, int, list[Attempt]]:
    """Find who is logged on to a host (hostname or IP).

    Methods are tried sequentially: WinRM -> WMI -> SMB.
    Each method is capped by per_method_timeout_s (seconds).
    """
    started = time.perf_counter()

    targets = _normalize_targets(raw_target, domain_suffix)
    if not targets:
        return [], "", 0, [Attempt("input", "error", "Пустой хост или IP.", 0, [])]

    per_method_timeout_s = int(per_method_timeout_s or 60)
    if per_method_timeout_s < 5:
        per_method_timeout_s = 5
    if per_method_timeout_s > 300:
        per_method_timeout_s = 300

    winrm_user, smb_domain, smb_user = _split_credential(query_username, domain_suffix)
    if not (winrm_user and smb_user and query_password):
        return [], "", 0, [Attempt("config", "error", "Не заданы учётные данные для опроса хостов (host query user/password) в настройках.", 0, [])]

    attempts: list[Attempt] = []

    def try_winrm() -> list[str]:
        last: Exception | None = None
        for t in targets:
            try:
                return _winrm_query_users(t, winrm_user, query_password, per_method_timeout_s)
            except ImportError:
                raise
            except Exception as e:
                last = e
                continue
        raise RuntimeError(str(last) if last else "WinRM ошибка")

    def try_wmi() -> list[str]:
        last: Exception | None = None
        for t in targets:
            try:
                return _wmi_query_user(t, smb_domain, smb_user, query_password)
            except ImportError:
                raise
            except Exception as e:
                last = e
                continue
        raise RuntimeError(str(last) if last else "WMI ошибка")

    def try_smb() -> list[str]:
        last: Exception | None = None
        for t in targets:
            try:
                return _smb_query_users(t, smb_domain, smb_user, query_password)
            except ImportError:
                raise
            except Exception as e:
                last = e
                continue
        raise RuntimeError(str(last) if last else "SMB ошибка")

    methods = [
        ("WinRM", try_winrm),
        ("WMI", try_wmi),
        ("SMB", try_smb),
    ]

    for name, fn in methods:
        t0 = time.perf_counter()
        try:
            users = _run_with_timeout(fn, per_method_timeout_s)
            users = _dedupe_users(users or [])
            elapsed = int((time.perf_counter() - t0) * 1000)

            if users:
                attempts.append(Attempt(name, "ok", "Найдено.", elapsed, users))
                total = int((time.perf_counter() - started) * 1000)
                return users, name, total, attempts

            attempts.append(Attempt(name, "empty", "Ответ получен, но активные пользователи не обнаружены.", elapsed, []))
        except concurrent.futures.TimeoutError:
            elapsed = int((time.perf_counter() - t0) * 1000)
            attempts.append(Attempt(name, "timeout", f"Таймаут {per_method_timeout_s} сек.", elapsed, []))
        except ImportError as e:
            elapsed = int((time.perf_counter() - t0) * 1000)
            attempts.append(Attempt(name, "skipped", f"Библиотека не установлена: {e}", elapsed, []))
        except Exception as e:
            elapsed = int((time.perf_counter() - t0) * 1000)
            msg = (str(e) or "Ошибка")[:300]
            attempts.append(Attempt(name, "error", msg, elapsed, []))

    total = int((time.perf_counter() - started) * 1000)
    return [], "", total, attempts
