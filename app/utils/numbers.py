from __future__ import annotations


def clamp_int(
    value,
    *,
    default: int,
    min_v: int | None = None,
    max_v: int | None = None,
) -> int:
    """Best-effort int conversion with optional clamping.

    - If conversion fails -> default.
    - If min_v/max_v provided -> clamp to bounds.

    NOTE: keep this helper dependency-light (no FastAPI imports).
    """
    try:
        v = int(value)
    except Exception:
        v = int(default)

    if min_v is not None and v < int(min_v):
        v = int(min_v)
    if max_v is not None and v > int(max_v):
        v = int(max_v)
    return v
