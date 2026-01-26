import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from .env_settings import get_env


class Base(DeclarativeBase):
    pass


def _db_url() -> str:
    s = get_env()
    db_dir = os.path.dirname(s.sqlite_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    return f"sqlite:///{s.sqlite_path}"


engine = create_engine(_db_url(), echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
