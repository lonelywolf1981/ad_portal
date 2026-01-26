from __future__ import annotations

from contextlib import contextmanager
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import AppSettings, LocalUser


@contextmanager
def db_session() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_or_create_settings(db: Session) -> AppSettings:
    st = db.get(AppSettings, 1)
    if st:
        return st
    st = AppSettings(id=1)
    db.add(st)
    db.commit()
    db.refresh(st)
    return st


def get_local_user(db: Session, username: str) -> LocalUser | None:
    return db.scalar(select(LocalUser).where(LocalUser.username == username))


def ensure_bootstrap_admin(db: Session, username: str, password_hash: str) -> None:
    exists = db.scalar(select(LocalUser.id).limit(1))
    if exists:
        return
    u = LocalUser(username=username, password_hash=password_hash, is_admin=True, is_enabled=True)
    db.add(u)
    db.commit()
