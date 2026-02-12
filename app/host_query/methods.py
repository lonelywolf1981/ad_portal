from __future__ import annotations

from ..utils.tcp_probe import tcp_probe
from ..env_settings import get_env
from .utils import dedupe_users


def _decode_winrm_output(raw: bytes) -> str:
    """Декодирование вывода WinRM/PowerShell с fallback по кодировкам.

    PowerShell может отдавать в UTF-8 (если OutputEncoding выставлен),
    в OEM-кодировке (cp866 для русской Windows) или ANSI (cp1251).
    Пробуем UTF-8 → cp866 → cp1251.
    """
    if not raw:
        return ""
    # UTF-8 BOM
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    # Попытка UTF-8 (strict)
    try:
        text = raw.decode("utf-8")
        # Если декодировалось без ошибок — используем
        return text
    except UnicodeDecodeError:
        pass
    # Fallback: cp866 (OEM Russian)
    try:
        return raw.decode("cp866")
    except UnicodeDecodeError:
        pass
    # Fallback: cp1251 (ANSI Russian)
    try:
        return raw.decode("cp1251")
    except UnicodeDecodeError:
        pass
    # Последний fallback
    return raw.decode("utf-8", errors="replace")


def _safe_str(val) -> str:
    """Безопасное преобразование значения из impacket в строку."""
    if val is None:
        return ""
    if isinstance(val, bytes):
        try:
            return val.decode("utf-16-le").rstrip("\x00").strip()
        except UnicodeDecodeError:
            try:
                return val.decode("utf-8").rstrip("\x00").strip()
            except UnicodeDecodeError:
                return val.decode("latin-1").rstrip("\x00").strip()
    return str(val).rstrip("\x00").strip()


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
    insecure_tls = bool(get_env().host_query_winrm_insecure)
    for ep in endpoints:
        try:
            cert_validation = "ignore" if (insecure_tls and ep.startswith("https://")) else "validate"
            sess = winrm.Session(
                ep,
                auth=(username, password),
                transport="ntlm",
                server_cert_validation=cert_validation,
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


def winrm_enum_shares(target: str, username: str, password: str, per_method_timeout_s: int) -> list[dict]:
    """WinRM: перечисление шар через Get-SmbShare (самый эффективный в домене).

    Возвращает список словарей:
      {"name": str, "type": int, "remark": str}
    """
    import winrm  # type: ignore

    endpoints: list[str] = []
    if tcp_probe(target, 5985, timeout_s=2.0):
        endpoints.append(f"http://{target}:5985/wsman")
    if tcp_probe(target, 5986, timeout_s=2.0):
        endpoints.append(f"https://{target}:5986/wsman")

    if not endpoints:
        raise RuntimeError("WinRM порты 5985/5986 недоступны")

    op_timeout = max(10, min(30, per_method_timeout_s - 10))
    read_timeout = max(op_timeout + 5, min(per_method_timeout_s - 2, op_timeout + 15))

    # Get-SmbShare возвращает Name, ShareType (uint32), Description
    # ShareType: 0=Disk, 1=PrintQueue, 2=Device, 3=IPC,
    #   с битом 0x80000000 для скрытых (Special)
    ps = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
try {
  $shares = Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, ShareType, Description
  foreach ($s in $shares) {
    $t = 0
    try { $t = [uint32]$s.ShareType } catch { $t = 0 }
    $n = ($s.Name -as [string]).Trim()
    $d = ($s.Description -as [string]).Trim()
    if ($n) { "$n`t$t`t$d" }
  }
} catch {
  # Fallback: net share
  $lines = (net share 2>$null) | Select-Object -Skip 1
  foreach ($l in $lines) {
    $l = ($l -as [string])
    if (-not $l -or $l.StartsWith('---') -or $l.StartsWith('The command')) { continue }
    $parts = $l -split '\s{2,}', 3
    if ($parts.Count -ge 1) {
      $n = $parts[0].Trim()
      $d = if ($parts.Count -ge 3) { $parts[2].Trim() } else { '' }
      if ($n) { "$n`t0`t$d" }
    }
  }
}
"""

    insecure_tls = bool(get_env().host_query_winrm_insecure)
    last_err: Exception | None = None
    for ep in endpoints:
        try:
            cert_validation = "ignore" if (insecure_tls and ep.startswith("https://")) else "validate"
            sess = winrm.Session(
                ep,
                auth=(username, password),
                transport="ntlm",
                server_cert_validation=cert_validation,
                read_timeout_sec=read_timeout,
                operation_timeout_sec=op_timeout,
            )
            r = sess.run_ps(ps)
            if r.status_code != 0:
                err = (r.std_err or b"").decode("utf-8", errors="replace")[:400]
                raise RuntimeError(err or "Команда завершилась с ошибкой")
            raw = r.std_out or b""
            # WinRM + PowerShell: пробуем UTF-8, затем cp866 (OEM), затем cp1251 (ANSI)
            out = _decode_winrm_output(raw)
            shares: list[dict] = []
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split("\t", 2)
                name = parts[0].strip() if len(parts) > 0 else ""
                try:
                    stype = int(parts[1].strip()) if len(parts) > 1 else 0
                except (ValueError, IndexError):
                    stype = 0
                remark = parts[2].strip() if len(parts) > 2 else ""
                if name:
                    shares.append({"name": name, "type": stype, "remark": remark})
            return shares
        except Exception as e:
            last_err = e
            continue

    raise RuntimeError(str(last_err) if last_err else "WinRM ошибка")


def wmi_enum_shares(target: str, domain: str, username: str, password: str) -> list[dict]:
    """WMI/DCOM: перечисление шар через Win32_Share.

    Возвращает список словарей:
      {"name": str, "type": int, "remark": str}
    """
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

        query = "SELECT Name, Type, Description FROM Win32_Share"
        iEnum = iWbemServices.ExecQuery("WQL", query)

        shares: list[dict] = []
        while True:
            try:
                item = iEnum.Next(0xFFFFFFFF, 1)[0]
            except Exception:
                break
            try:
                props = item.getProperties()
                name = _safe_str(props.get("Name", {}).get("value"))
                stype = int(props.get("Type", {}).get("value") or 0)
                remark = _safe_str(props.get("Description", {}).get("value"))
                if name:
                    shares.append({"name": name, "type": stype, "remark": remark})
            except Exception:
                continue

        return shares
    finally:
        try:
            if dcom is not None:
                dcom.disconnect()
        except Exception:
            pass


def smb_enum_shares(target: str, domain: str, username: str, password: str) -> list[dict]:
    """Перечисление SMB-шар через srvsvc.hNetrShareEnum (level 1).

    Возвращает список словарей:
      {"name": str, "type": int, "remark": str}
    """
    from impacket.smbconnection import SMBConnection  # type: ignore
    from impacket.dcerpc.v5 import transport, srvsvc  # type: ignore

    if not tcp_probe(target, 445, timeout_s=2.0):
        raise RuntimeError("SMB порт 445 недоступен")

    smb = SMBConnection(remoteName=target, remoteHost=target, sess_port=445, timeout=7)
    smb.login(username, password, domain)

    shares: list[dict] = []
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
        resp = srvsvc.hNetrShareEnum(dce, "\\\\" + target, 1)
        dce.disconnect()

        info = resp.get("InfoStruct", {})
        share_info = info.get("ShareInfo", {})
        level1 = share_info.get("Level1", {})
        buf = level1.get("Buffer", [])
        for entry in buf or []:
            try:
                name = _safe_str(entry.get("shi1_netname"))
                shi_type = int(entry.get("shi1_type", 0) or 0)
                remark = _safe_str(entry.get("shi1_remark"))
                if name:
                    shares.append({"name": name, "type": shi_type, "remark": remark})
            except Exception:
                continue
    finally:
        try:
            smb.logoff()
        except Exception:
            pass

    return shares


def winrm_close_share(target: str, username: str, password: str, share_name: str, per_method_timeout_s: int) -> tuple[bool, str]:
    """WinRM: закрыть SMB-шару (Remove-SmbShare, fallback net share /delete)."""
    import winrm  # type: ignore

    share_name = (share_name or "").strip()
    if not share_name:
        return False, "Пустое имя ресурса."

    endpoints: list[str] = []
    if tcp_probe(target, 5985, timeout_s=2.0):
        endpoints.append(f"http://{target}:5985/wsman")
    if tcp_probe(target, 5986, timeout_s=2.0):
        endpoints.append(f"https://{target}:5986/wsman")

    if not endpoints:
        return False, "WinRM порты 5985/5986 недоступны"

    op_timeout = max(10, min(30, per_method_timeout_s - 10))
    read_timeout = max(op_timeout + 5, min(per_method_timeout_s - 2, op_timeout + 15))
    escaped = share_name.replace("'", "''")

    ps = rf"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$name = '{escaped}'
try {{
  $exists = Get-SmbShare -Name $name -ErrorAction SilentlyContinue
  if (-not $exists) {{
    Write-Output "NOT_FOUND"
    exit 0
  }}
}} catch {{}}

try {{
  Remove-SmbShare -Name $name -Force -Confirm:$false -ErrorAction Stop | Out-Null
  Write-Output "OK"
  exit 0
}} catch {{}}

try {{
  net share $name /delete /y | Out-Null
  if ($LASTEXITCODE -eq 0) {{
    Write-Output "OK"
  }} else {{
    Write-Output "ERROR: net share exit $LASTEXITCODE"
  }}
}} catch {{
  Write-Output ("ERROR: " + $_.Exception.Message)
}}
"""

    insecure_tls = bool(get_env().host_query_winrm_insecure)
    last_err: Exception | None = None
    for ep in endpoints:
        try:
            cert_validation = "ignore" if (insecure_tls and ep.startswith("https://")) else "validate"
            sess = winrm.Session(
                ep,
                auth=(username, password),
                transport="ntlm",
                server_cert_validation=cert_validation,
                read_timeout_sec=read_timeout,
                operation_timeout_sec=op_timeout,
            )
            r = sess.run_ps(ps)
            out = _decode_winrm_output(r.std_out or b"").strip().upper()
            if "NOT_FOUND" in out:
                return False, "Ресурс не найден на хосте."
            if "OK" in out and "ERROR" not in out:
                return True, "Ресурс закрыт."
            err = _decode_winrm_output(r.std_err or b"").strip()
            if err:
                return False, err[:300]
            if out:
                return False, out[:300]
            return False, "Не удалось закрыть ресурс."
        except Exception as e:
            last_err = e
            continue

    return False, (str(last_err) if last_err else "WinRM ошибка")
