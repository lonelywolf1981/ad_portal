from __future__ import annotations

from ..utils.tcp_probe import tcp_probe
from .utils import dedupe_users


def winrm_query_users(target: str, username: str, password: str, per_method_timeout_s: int) -> list[str]:
    """WinRM: try `quser`, fallback to Win32_ComputerSystem.UserName."""
    import winrm  # type: ignore

    endpoints: list[str] = []
    # Quick probes to avoid long hangs
    if tcp_probe(target, 5985, timeout_s=2.0):
        endpoints.append(f"http://{target}:5985/wsman")
    if tcp_probe(target, 5986, timeout_s=2.0):
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
            return dedupe_users(users)
        except Exception as e:
            last_err = e
            continue

    raise RuntimeError(str(last_err) if last_err else "WinRM ошибка")


def wmi_query_user(target: str, domain: str, username: str, password: str) -> list[str]:
    """WMI/DCOM: query Win32_ComputerSystem.UserName."""
    if not tcp_probe(target, 135, timeout_s=2.0):
        raise RuntimeError("WMI/RPC порт 135 недоступен")

    from impacket.dcerpc.v5.dcomrt import DCOMConnection  # type: ignore
    from impacket.dcerpc.v5.dcom import wmi  # type: ignore
    from impacket.dcerpc.v5.dtypes import NULL  # type: ignore

    dcom = None
    try:
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

        return dedupe_users(users)
    finally:
        try:
            if dcom is not None:
                dcom.disconnect()
        except Exception:
            pass


def smb_query_users(target: str, domain: str, username: str, password: str) -> list[str]:
    """SMB/RPC: wkssvc (interactive users) then srvsvc (network sessions)."""
    from impacket.smbconnection import SMBConnection  # type: ignore
    from impacket.dcerpc.v5 import transport, wkst, srvsvc  # type: ignore
    from impacket.dcerpc.v5.rpcrt import DCERPCException  # type: ignore

    if not tcp_probe(target, 445, timeout_s=2.0):
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

    return dedupe_users(users)
