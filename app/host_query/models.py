from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Attempt:
    method: str
    status: str  # ok | empty | timeout | error | skipped
    message: str
    elapsed_ms: int
    users: list[str]
