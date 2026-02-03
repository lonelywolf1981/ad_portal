from __future__ import annotations

import concurrent.futures
import time

from .credentials import split_credential
from .methods import smb_query_users, winrm_query_users, wmi_query_user
from .models import Attempt
from .targets import normalize_targets
from .utils import dedupe_users, run_with_timeout


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

    targets = normalize_targets(raw_target, domain_suffix)
    if not targets:
        return [], "", 0, [Attempt("input", "error", "Пустой хост или IP.", 0, [])]

    per_method_timeout_s = int(per_method_timeout_s or 60)
    if per_method_timeout_s < 5:
        per_method_timeout_s = 5
    if per_method_timeout_s > 300:
        per_method_timeout_s = 300

    winrm_user, smb_domain, smb_user = split_credential(query_username, domain_suffix)
    if not (winrm_user and smb_user and query_password):
        return (
            [],
            "",
            0,
            [
                Attempt(
                    "config",
                    "error",
                    "Не заданы учётные данные для опроса хостов (host query user/password) в настройках.",
                    0,
                    [],
                )
            ],
        )

    attempts: list[Attempt] = []

    def try_winrm() -> list[str]:
        last: Exception | None = None
        for t in targets:
            try:
                return winrm_query_users(t, winrm_user, query_password, per_method_timeout_s)
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
                return wmi_query_user(t, smb_domain, smb_user, query_password)
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
                return smb_query_users(t, smb_domain, smb_user, query_password)
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
            users = run_with_timeout(fn, per_method_timeout_s)
            users = dedupe_users(users or [])
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
