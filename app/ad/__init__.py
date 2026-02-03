"""Active Directory (LDAP) client package.

Stage 2 refactor: split former `ldap_client.py` into a package.

Public API kept stable:
    - ADConfig
    - ADUser
    - ADClient
"""

from .models import ADConfig, ADUser
from .client import ADClient

__all__ = ["ADConfig", "ADUser", "ADClient"]
