"""Host query package.

This package contains logic for determining who is currently logged on to a
Windows host via WinRM/WMI/SMB.

Public API:
    - find_logged_on_users()
    - Attempt
"""

from .api import find_logged_on_users
from .models import Attempt

__all__ = ["find_logged_on_users", "Attempt"]
