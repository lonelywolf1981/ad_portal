import os
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from .env_settings import get_env


class Base(DeclarativeBase):
    pass


def _db_url() -> str:
    s = get_env()
    sqlite_path = (s.sqlite_path or "").strip() or "data/app.db"
    p = Path(sqlite_path)
    if not p.is_absolute():
        # Resolve relative DB paths against project root (/app), not process CWD.
        project_root = Path(__file__).resolve().parents[1]
        p = (project_root / p).resolve()

    db_dir = str(p.parent)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    return f"sqlite:///{p.as_posix()}"


engine = create_engine(
    _db_url(),
    echo=False,
    future=True,
    connect_args={"check_same_thread": False},
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    # WAL is faster, but can fail on some filesystems (e.g. Docker bind mounts on Windows/WSL2).
    # Do best-effort to avoid taking down the whole app when WAL is unsupported.
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
    except Exception:
        try:
            cursor.execute("PRAGMA journal_mode=DELETE")
        except Exception:
            pass
    try:
        cursor.execute("PRAGMA busy_timeout=5000")
    except Exception:
        pass
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
