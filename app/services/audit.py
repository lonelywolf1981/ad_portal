from __future__ import annotations

from sqlalchemy.orm import Session

from ..models import LoginAudit


def audit_login(
    db: Session,
    username: str,
    auth_type: str,
    success: bool,
    ip: str,
    ua: str,
    result_code: str,
    details: str = "",
) -> None:
    db.add(
        LoginAudit(
            username=username,
            auth_type=auth_type,
            success=success,
            ip=ip,
            user_agent=ua,
            result_code=result_code,
            details=details[:512],
        )
    )
    db.commit()
