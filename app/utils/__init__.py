"""Small, side-effect free helpers used across routers.

Keep this package dependency-light to avoid circular imports.
"""

from .numbers import clamp_int  # noqa: F401
