from __future__ import annotations

import concurrent.futures

_TIMEOUT_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=32,
    thread_name_prefix="host-query-timeout",
)


def dedupe_users(users: list[str]) -> list[str]:
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


def run_with_timeout(fn, timeout_s: int):
    """Run in a shared worker pool and enforce timeout."""
    fut = _TIMEOUT_EXECUTOR.submit(fn)
    try:
        return fut.result(timeout=timeout_s)
    except concurrent.futures.TimeoutError:
        fut.cancel()
        raise
