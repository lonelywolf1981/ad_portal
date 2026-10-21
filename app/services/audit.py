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


def audit_action(request, auth: dict, auth_type: str, action: str, success: bool, details: str = "") -> None:
    """Записать действие пользователя портала (не вход) в тот же журнал аудита.

    Ошибка записи аудита не должна ломать само действие.
    """
    import logging

    from ..repo import db_session

    try:
        with db_session() as db:
            audit_login(
                db,
                username=str(auth.get("username", "?")),
                auth_type=auth_type,
                success=success,
                ip=request.client.host if request.client else "?",
                ua=request.headers.get("user-agent", ""),
                result_code=action,
                details=details,
            )
    except Exception:
        logging.getLogger(__name__).warning("Не удалось записать аудит: %s %s", auth_type, action)
