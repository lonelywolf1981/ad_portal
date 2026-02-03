from __future__ import annotations

import concurrent.futures


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
    """Run in a worker thread and enforce timeout without waiting on shutdown."""
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(fn)
    try:
        return fut.result(timeout=timeout_s)
    finally:
        # Important: do NOT wait here; otherwise timeouts are ineffective.
        ex.shutdown(wait=False, cancel_futures=True)
