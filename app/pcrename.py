"""Rename a domain PC for the bot (infra-ops action pc-rename -> POST /api/v1/pc-rename). 21.10.2026.

plan  — only reads: AD (old/new name), DNS, the PC itself over WinRM (svc-hostquery, Kerberos): who is logged on,
        cable / Wi-Fi, Wi-Fi certificate, pending reboot, secure channel.
apply — on the PC (WinRM): Rename-Computer with svc-pcrename (may only rename computer objects in OU=Компьютеры,
        Компьютеры-особые, CN=Computers), a one-shot startup task that after the reboot replaces the Wi-Fi certificate
        (template JSQWiFiComputer, issued for the old name) and re-registers DNS, and a reboot at the given time with a
        5-minute warning to the user. A Celery task then checks the PC under the new name (AD, DNS, certificate) and
        stores the result; the agent's renamewatch reports it to Telegram.
Rules (user, 21.10.2026): the new name must match the template ОТДЕЛ-цифры (e.g. FIN-00051, MONOBLOK-02991), ≤ 15
characters; servers, DCs and APP1 are never renamed. Jobs: Redis adp:pcrename:jobs (last 100).
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import socket
import time
import uuid
from datetime import datetime, timedelta

log = logging.getLogger(__name__)

JOBS_KEY = "adp:pcrename:jobs"
DOMAIN = "ubc.local.net"
NAME_RE = re.compile(r"^[A-Z][A-Z0-9]{1,9}-\d{4,9}$")
ALLOWED_CONTAINERS = ("OU=Компьютеры,DC=ubc,DC=local,DC=net", "OU=Компьютеры-особые,DC=ubc,DC=local,DC=net",
                      "CN=Computers,DC=ubc,DC=local,DC=net")
NEVER = {"APP1"}
WIFI_TEMPLATE = "JSQWiFiComputer"
# OID of the template: the extension text is localized ("Шаблон=JSQ WiFi Computer(OID)…"), the OID is not
WIFI_TEMPLATE_OID = "1.3.6.1.4.1.311.21.8.14793886.10795684.6113926.9003114.4402986.151.1.39532874.88814959"
OLD_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,14}$")


# ---------- helpers ----------

def _ps(host_fqdn: str, script: str, timeout_s: int = 90) -> str:
    """Run PowerShell on the PC as svc-hostquery (Kerberos, encrypted WinRM). Returns stdout; raises on error."""
    import winrm  # type: ignore

    from .host_query import kerberos
    from .crypto import decrypt_str
    from .repo import db_session, get_or_create_settings

    with db_session() as db:
        st = get_or_create_settings(db)
        q_user, q_pass = (st.host_query_username or "").strip(), decrypt_str(st.host_query_password_enc or "")
    user, realm = kerberos.split_principal(q_user, DOMAIN)
    kerberos.ensure_ticket(q_user, q_pass, DOMAIN)
    s = winrm.Session(f"http://{host_fqdn}:5985/wsman", auth=(f"{user}@{realm}", q_pass), transport="kerberos",
                      server_cert_validation="validate", read_timeout_sec=timeout_s + 10, operation_timeout_sec=timeout_s)
    # UTF-8 output; the script is passed as -EncodedCommand by pywinrm
    r = s.run_ps("[Console]::OutputEncoding=[Text.Encoding]::UTF8\n" + script)
    out = (r.std_out or b"").decode("utf-8", errors="replace")
    if r.status_code != 0:
        err = (r.std_err or b"").decode("utf-8", errors="replace")
        raise RuntimeError((err or out or "ошибка PowerShell").strip()[:500])
    return out


def _ldap():
    from .ad import ADClient
    from .repo import db_session, get_or_create_settings
    from .services.ad import ad_cfg_from_settings

    with db_session() as db:
        cfg = ad_cfg_from_settings(get_or_create_settings(db))
    cl = ADClient(cfg)
    c = cl._conn(cl.cfg.bind_principal, cl.cfg.bind_password)
    if not c.bind():
        raise RuntimeError(f"AD bind: {c.result.get('description')}")
    return c


def _find_computer(c, name: str) -> dict | None:
    from ldap3 import SUBTREE

    c.search("DC=ubc,DC=local,DC=net", f"(&(objectCategory=computer)(sAMAccountName={name}$))", SUBTREE,
             attributes=["distinguishedName", "operatingSystem", "dNSHostName", "userAccountControl", "objectGUID"])
    if not c.entries:
        return None
    e = c.entries[0]
    return {"dn": str(e.distinguishedName), "os": str(e.operatingSystem or ""), "dns": str(e.dNSHostName or ""),
            "uac": int(e.userAccountControl.value or 0), "guid": str(e.objectGUID)}


def _resolve(name: str) -> list[str]:
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(f"{name}.{DOMAIN}", None, socket.AF_INET)})
    except socket.gaierror:
        return []


def _reboot_time(s: str) -> tuple[datetime | None, str]:
    """'HH:MM' -> (time, note): later today, or tomorrow if it has already passed (noted); less than 7 min
    from now -> error (the 5-minute warning would not fit); 'now' -> in 6 minutes."""
    s = (s or "").strip().lower()
    now = datetime.now()
    if s in ("now", "сейчас"):
        return now + timedelta(minutes=6), ""
    m = re.match(r"^(\d{1,2}):(\d{2})$", s)
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        return None, f"время перезагрузки «{s}»: нужно ЧЧ:ММ или now"
    t = now.replace(hour=int(m.group(1)), minute=int(m.group(2)), second=0, microsecond=0)
    if now <= t < now + timedelta(minutes=7):
        return None, f"до {s} меньше 7 минут — предупреждение за 5 минут не успеет; укажите время позже или now"
    if t < now:
        return t + timedelta(days=1), f"⚠️ {s} сегодня уже прошло — перезагрузка ЗАВТРА {t + timedelta(days=1):%d.%m} в {s}"
    return t, ""


_PROBE = r"""
$o = [ordered]@{}
$o.hostname = $env:COMPUTERNAME
$o.os = (Get-CimInstance Win32_OperatingSystem).Caption
$o.users = @(try { (quser 2>$null | Select-Object -Skip 1 | ForEach-Object { ($_.Trim() -split '\s+')[0].Trim('>') }) } catch { })
$o.adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | ForEach-Object {
    @{ name = $_.Name; kind = $(if ($_.NdisPhysicalMedium -eq 9 -or $_.InterfaceDescription -match 'Wi-?Fi|Wireless|802\.11') { 'wifi' } else { 'ethernet' }); speed = $_.LinkSpeed } })
$o.ssid = ((netsh wlan show interfaces 2>$null | Select-String '^\s+SSID\s+:' | Select-Object -First 1) -replace '^\s+SSID\s+:\s*', '')
$o.wifi_cert = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { ($_.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' } | ForEach-Object { $_.Format(0) }) -match '__TPL__' } | ForEach-Object { @{ subject = $_.Subject; dns = ($_.DnsNameList.Unicode -join ','); expires = $_.NotAfter.ToString('yyyy-MM-dd') } })
$o.pending_reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
$o.secure_channel = $(try { Test-ComputerSecureChannel } catch { $false })
$o.setup_running = [bool](Get-Process SetupHost -ErrorAction SilentlyContinue)
$o | ConvertTo-Json -Depth 4 -Compress
""".replace("__TPL__", re.escape(WIFI_TEMPLATE_OID))


# ---------- plan ----------

def plan(old: str, new: str, reboot_at: str) -> dict:
    old, new = (old or "").strip().upper().split(".")[0], (new or "").strip().upper()
    errors, warnings, info = [], [], {}
    when, note = _reboot_time(reboot_at)
    if not when:
        errors.append(note)
    elif note:
        warnings.append(note)
    if not NAME_RE.match(new) or len(new) > 15:
        errors.append(f"новое имя {new}: нужен шаблон ОТДЕЛ-цифры (буквы, дефис, 4–9 цифр; до 15 символов), например FIN-00051")
    if new == old:
        errors.append("новое имя совпадает со старым")
    if not OLD_RE.match(old):
        return {"ok": False, "old": old, "new": new, "reboot_at": None, "errors": [f"имя {old!r} недопустимо"], "warnings": [], "info": {}}
    if old in NEVER:
        errors.append(f"{old}: этот компьютер не переименовывается")
    c = _ldap()
    try:
        comp = _find_computer(c, old)
        if not comp:
            errors.append(f"{old}: компьютер не найден в AD")
        else:
            info["ad_dn"] = comp["dn"]
            if not any(comp["dn"].lower().endswith(x.lower()) for x in ALLOWED_CONTAINERS):
                errors.append(f"{old}: не в OU=Компьютеры / Компьютеры-особые / CN=Computers — переименование не разрешено")
            if "server" in comp["os"].lower() or comp["uac"] & 0x2000:
                errors.append(f"{old}: сервер или контроллер домена — не переименовывается")
            if comp["uac"] & 0x2:
                errors.append(f"{old}: учётка компьютера отключена в AD")
        if NAME_RE.match(new) and _find_computer(c, new):
            errors.append(f"{new}: такое имя уже есть в AD")
        # prefixes in use: a new one is allowed, but worth a look
        if NAME_RE.match(new):
            from ldap3 import SUBTREE
            pre = new.split("-")[0]
            c.search("DC=ubc,DC=local,DC=net", f"(&(objectCategory=computer)(sAMAccountName={pre}-*))", SUBTREE, attributes=["cn"])
            if not c.entries:
                warnings.append(f"префикс {pre}- ещё не используется ни у одного ПК — проверьте отдел")
    finally:
        c.unbind()
    if NAME_RE.match(new) and _resolve(new):
        errors.append(f"{new}.{DOMAIN} уже есть в DNS ({', '.join(_resolve(new))})")
    info["ip"] = _resolve(old)
    if not errors:
        try:
            p = json.loads(_ps(f"{old}.{DOMAIN}", _PROBE, 60).strip().splitlines()[-1])
        except Exception as e:  # noqa: BLE001
            p = None
            errors.append(f"{old}: компьютер не отвечает по WinRM ({str(e)[:160]}) — он должен быть включён и в сети")
        if p:
            info["probe"] = p
            if (p.get("hostname") or "").upper() != old:
                errors.append(f"по адресу {old} отвечает {p.get('hostname')} — DNS устарел, переименование отменено")
            if not p.get("secure_channel"):
                errors.append(f"{old}: нарушено доверие с доменом (secure channel) — сначала починить")
            if p.get("setup_running"):
                errors.append(f"{old}: идёт установка обновления Windows (SetupHost) — дождитесь окончания")
            if p.get("pending_reboot"):
                warnings.append("на ПК уже ожидает перезагрузка (обновления) — она совпадёт с переименованием")
            kinds = {a.get("kind") for a in (p.get("adapters") or [])}
            if "ethernet" not in kinds and "wifi" in kinds:
                warnings.append(f"ПК подключён только по Wi-Fi ({p.get('ssid') or '?'}). Сертификат Wi-Fi выписан на старое имя: "
                                "после перезагрузки сеть может не подключиться, и новый сертификат не придёт. Подключите кабель "
                                "до перезагрузки")
            if p.get("users"):
                warnings.append(f"сейчас за ПК: {', '.join(p['users'])} — за 5 минут до перезагрузки им придёт предупреждение")
    return {"ok": not errors, "old": old, "new": new, "reboot_at": when.strftime("%Y-%m-%d %H:%M") if when else None,
            "errors": errors, "warnings": warnings, "info": info}


# ---------- apply ----------

_POST_RENAME = r"""
# JSQ post-rename (one-shot, SYSTEM, at startup): new Wi-Fi certificate for the new name, DNS. ASCII only.
$d = 'C:\ProgramData\JSQ\Rename'; $r = [ordered]@{ started = (Get-Date).ToString('s'); host = $env:COMPUTERNAME }
function Save { $r.finished = (Get-Date).ToString('s'); $r | ConvertTo-Json | Set-Content "$d\result.json" -Encoding ascii }
try {
  $t0 = Get-Date
  while (-not (Test-Connection -ComputerName '__DC__' -Count 1 -Quiet) -and ((Get-Date) - $t0).TotalMinutes -lt 15) { Start-Sleep 20 }
  $r.network = Test-Connection -ComputerName '__DC__' -Count 1 -Quiet
  $fqdn = ($env:COMPUTERNAME + '.__DOMAIN__').ToLower()
  $tpl = { param($c) ($c.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' } | ForEach-Object { $_.Format(0) }) -match '__TPL__' }
  $old = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { (& $tpl $_) -and (($_.DnsNameList.Unicode -join ',').ToLower() -notmatch [regex]::Escape($fqdn)) })
  $r.old_certs = $old.Count
  if ($r.network) {
    certutil -pulse | Out-Null
    $t1 = Get-Date
    do { Start-Sleep 20; $new = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { (& $tpl $_) -and (($_.DnsNameList.Unicode -join ',').ToLower() -match [regex]::Escape($fqdn)) }) }
    while (-not $new -and $r.old_certs -and ((Get-Date) - $t1).TotalMinutes -lt 10)
    $r.new_cert = [bool]$new
    if ($new) { foreach ($c in $old) { Remove-Item "Cert:\LocalMachine\My\$($c.Thumbprint)" -Force }; $r.old_removed = $old.Count }
    ipconfig /registerdns | Out-Null; $r.dns_registered = $true
  }
} catch { $r.error = $_.Exception.Message }
Save
Unregister-ScheduledTask -TaskName 'JSQ post-rename' -Confirm:$false -ErrorAction SilentlyContinue
""".replace("__TPL__", re.escape(WIFI_TEMPLATE_OID)).replace("__DOMAIN__", DOMAIN).replace("__DC__", "dc1." + DOMAIN)

_REBOOT_MSG = "Компьютер переименован администратором. Перезагрузка через 5 минут — сохраните работу."


def _apply_script(new: str, when: datetime) -> str:
    user, pw = os.getenv("PCRENAME_USER", ""), os.getenv("PCRENAME_PASSWORD", "")
    if not user or not pw:
        raise RuntimeError("PCRENAME_USER/PCRENAME_PASSWORD не заданы в .env")
    b64 = lambda s: base64.b64encode(s.encode("utf-8")).decode()  # noqa: E731
    warn_at = when - timedelta(minutes=5)
    return f"""
$ErrorActionPreference = 'Stop'
$d = 'C:\\ProgramData\\JSQ\\Rename'; New-Item -ItemType Directory -Force $d | Out-Null
& icacls $d /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
Remove-Item "$d\\result.json" -ErrorAction SilentlyContinue
# post-rename.ps1 was uploaded in parts as base64 (post-rename.b64): the whole script does not fit one command line
[IO.File]::WriteAllText("$d\\post-rename.ps1", [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content "$d\\post-rename.b64" -Raw).Trim())), [Text.Encoding]::ASCII)
Remove-Item "$d\\post-rename.b64"
if ((Get-FileHash "$d\\post-rename.ps1" -Algorithm SHA256).Hash -ne '{hashlib.sha256(_POST_RENAME.encode("ascii")).hexdigest().upper()}') {{ throw 'post-rename.ps1: контрольная сумма не совпала' }}
$a =New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File $d\\post-rename.ps1"
$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 40) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'JSQ post-rename' -Action $a -Trigger (New-ScheduledTaskTrigger -AtStartup) -Settings $s -User SYSTEM -RunLevel Highest -Force | Out-Null
$cred = New-Object PSCredential('{user}', (ConvertTo-SecureString ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64(pw)}'))) -AsPlainText -Force))
$res = Rename-Computer -NewName '{new}' -DomainCredential $cred -Force -PassThru -WarningAction SilentlyContinue
if (-not $res.HasSucceeded) {{ Unregister-ScheduledTask -TaskName 'JSQ post-rename' -Confirm:$false; throw "Rename-Computer не выполнен" }}
$msg = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64(_REBOOT_MSG)}'))
$ra = New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument ('/r /t 300 /d p:2:4 /c "' + $msg + '"')
$rt = New-ScheduledTaskTrigger -Once -At ([datetime]'{warn_at:%Y-%m-%dT%H:%M:%S}')
Register-ScheduledTask -TaskName 'JSQ rename reboot' -Action $ra -Trigger $rt -User SYSTEM -RunLevel Highest -Force | Out-Null
'RENAMED ' + $res.OldComputerName + ' -> ' + $res.NewComputerName
"""


def apply(old: str, new: str, reboot_at: str) -> dict:
    p = plan(old, new, reboot_at)
    if not p["ok"]:
        return p
    when = datetime.strptime(p["reboot_at"], "%Y-%m-%d %H:%M")
    host = f"{p['old']}.{DOMAIN}"
    # Upload the post-reboot script in parts: a WinRM command line (-EncodedCommand) is limited to 8191 characters
    data = base64.b64encode(_POST_RENAME.encode("ascii")).decode()
    _ps(host, "$d='C:\\ProgramData\\JSQ\\Rename'; New-Item -ItemType Directory -Force $d | Out-Null; "
              "& icacls $d /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null; "
              "Set-Content \"$d\\post-rename.b64\" -Value '' -NoNewline -Encoding ascii; 'ok'", 60)
    for i in range(0, len(data), 2000):
        _ps(host, f"Add-Content 'C:\\ProgramData\\JSQ\\Rename\\post-rename.b64' -Value '{data[i:i + 2000]}' -NoNewline -Encoding ascii; 'ok'", 60)
    out = _ps(host, _apply_script(p["new"], when), 120)
    job = {"id": uuid.uuid4().hex[:10], "old": p["old"], "new": p["new"], "reboot_at": p["reboot_at"],
           "ip": p["info"].get("ip"), "created": datetime.now().strftime("%Y-%m-%d %H:%M"), "status": "scheduled",
           "result": None, "warnings": p["warnings"], "output": out.strip()[-300:]}
    _save(job)
    from .tasks import pcrename_check
    pcrename_check.apply_async(args=[job["id"]], eta=when + timedelta(minutes=8))
    return {**p, "applied": True, "job": job}


# ---------- after the reboot ----------

def check(job_id: str, attempt: int = 0) -> dict | None:
    """Look at the PC under the new name. Retries every 10 min, up to 3 hours after the reboot."""
    job = get_job(job_id)
    if not job or job["status"] not in ("scheduled", "waiting"):
        return job
    res = {"ad_dns_name": None, "dns_new": _resolve(job["new"]), "dns_old": _resolve(job["old"]), "pc": None}
    c = _ldap()
    try:
        comp = _find_computer(c, job["new"])
        res["ad_dns_name"] = comp["dns"] if comp else None
        res["ad_old_still"] = bool(_find_computer(c, job["old"]))
    finally:
        c.unbind()
    try:
        out = _ps(f"{job['new']}.{DOMAIN}", r"if (Test-Path C:\ProgramData\JSQ\Rename\result.json) { Get-Content C:\ProgramData\JSQ\Rename\result.json -Raw } else { '{}' }", 40)
        res["pc"] = json.loads(out.strip() or "{}")
    except Exception as e:  # noqa: BLE001
        res["pc_error"] = str(e)[:200]
    done = bool(res["pc"] and res["pc"].get("finished"))
    if not done and attempt < 18:
        job.update(status="waiting", result=res)
        _save(job)
        from .tasks import pcrename_check
        pcrename_check.apply_async(args=[job_id, attempt + 1], countdown=600)
        return job
    pc = res.get("pc") or {}
    ok = done and (res["ad_dns_name"] or "").lower().startswith(job["new"].lower()) and not pc.get("error")
    try:
        # cleanup of the one-shot reboot task (setup does not run here, but a migrated copy must not survive)
        _ps(f"{job['new']}.{DOMAIN}", "Unregister-ScheduledTask -TaskName 'JSQ rename reboot' -Confirm:$false -ErrorAction SilentlyContinue; 'ok'", 30)
    except Exception:  # noqa: BLE001
        pass
    job.update(status="done" if ok else "failed", result=res, checked=datetime.now().strftime("%Y-%m-%d %H:%M"))
    _save(job)
    return job


# ---------- jobs ----------

def _redis():
    from .session import _redis as r
    return r()


def _save(job: dict) -> None:
    r = _redis()
    r.hset(JOBS_KEY, job["id"], json.dumps(job, ensure_ascii=False))
    ids = sorted(r.hkeys(JOBS_KEY), key=lambda k: json.loads(r.hget(JOBS_KEY, k)).get("created", ""))
    for k in ids[:-100]:
        r.hdel(JOBS_KEY, k)


def get_job(job_id: str) -> dict | None:
    v = _redis().hget(JOBS_KEY, job_id)
    return json.loads(v) if v else None


def list_jobs() -> list[dict]:
    r = _redis()
    return sorted((json.loads(v) for v in r.hvals(JOBS_KEY)), key=lambda j: j.get("created", ""), reverse=True)
