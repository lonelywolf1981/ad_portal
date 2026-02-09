import os
from sqlalchemy import create_engine, event
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


engine = create_engine(
    _db_url(),
    echo=False,
    future=True,
    connect_args={"check_same_thread": False},
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
