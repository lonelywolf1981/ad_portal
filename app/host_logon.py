"""Backward-compatible shim.

The host query logic was moved to :mod:`app.host_query` (Stage 2 refactor).
Keep this module to avoid touching all import sites at once.
"""

from __future__ import annotations

from .host_query import Attempt, find_logged_on_users

__all__ = ["Attempt", "find_logged_on_users"]
