"""Backward-compatible shim.

The LDAP/AD client was moved to :mod:`app.ad` (Stage 2 refactor).
Keep this module to avoid touching all import sites at once.
"""

from __future__ import annotations

from .ad import ADClient, ADConfig, ADUser

__all__ = ["ADClient", "ADConfig", "ADUser"]
