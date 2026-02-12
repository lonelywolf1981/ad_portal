"""Настройка логирования приложения.

Файлы логов хранятся в директории `logs/` (относительно CWD),
организованы по дате через TimedRotatingFileHandler.

- Ротация: ежедневно (midnight).
- Хранение: настраивается через log_retention_days (по умолчанию 30).
- Максимальный размер: RotatingFileHandler с maxBytes (log_max_size_mb).
- Уровень: настраивается через log_level (по умолчанию INFO).
"""
from __future__ import annotations

import logging
import os
import glob
import time
from datetime import datetime, timedelta
from logging.handlers import TimedRotatingFileHandler, RotatingFileHandler

_LOG_DIR = os.path.join(os.getcwd(), "data", "logs")
_LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Отслеживаем установленный handler, чтобы при реконфигурации удалять старый.
_file_handler: logging.Handler | None = None
_console_handler: logging.Handler | None = None


def _ensure_log_dir() -> str:
    """Создаёт директорию логов, если не существует."""
    os.makedirs(_LOG_DIR, exist_ok=True)
    return _LOG_DIR


def setup_logging(
    level: str = "INFO",
    retention_days: int = 30,
    max_size_mb: int = 50,
) -> None:
    """Настраивает корневой логгер приложения.

    - Файловый handler: ротация по дате + по размеру.
    - Консольный handler: для docker-compose logs / stdout.
    - Уровень применяется ко всем.
    """
    global _file_handler, _console_handler

    level_str = (level or "INFO").strip().upper()
    if level_str not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        level_str = "INFO"
    log_level = getattr(logging, level_str, logging.INFO)

    retention_days = max(1, min(365, int(retention_days or 30)))
    max_size_mb = max(5, min(500, int(max_size_mb or 50)))

    root = logging.getLogger()

    # Удаляем предыдущие наши handlers (при реконфигурации)
    if _file_handler and _file_handler in root.handlers:
        root.removeHandler(_file_handler)
        try:
            _file_handler.close()
        except Exception:
            pass
    if _console_handler and _console_handler in root.handlers:
        root.removeHandler(_console_handler)

    log_dir = _ensure_log_dir()
    log_file = os.path.join(log_dir, "app.log")

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE_FORMAT)

    # TimedRotatingFileHandler — ротация по дате (midnight), хранение retention_days файлов.
    fh = TimedRotatingFileHandler(
        log_file,
        when="midnight",
        interval=1,
        backupCount=retention_days,
        encoding="utf-8",
        utc=True,
    )
    fh.suffix = "%Y-%m-%d"
    fh.setLevel(log_level)
    fh.setFormatter(formatter)
    _file_handler = fh

    # Консольный handler
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    ch.setFormatter(formatter)
    _console_handler = ch

    root.setLevel(log_level)
    root.addHandler(fh)
    root.addHandler(ch)

    # Очистка старых файлов, которые могли остаться от предыдущих retention настроек
    _cleanup_old_logs(log_dir, retention_days)

    # Подавляем слишком шумные логгеры
    logging.getLogger("uvicorn.access").setLevel(max(log_level, logging.WARNING))
    logging.getLogger("httpcore").setLevel(max(log_level, logging.WARNING))
    logging.getLogger("httpx").setLevel(max(log_level, logging.WARNING))

    logging.getLogger("app").info(
        "Логирование настроено: уровень=%s, хранение=%d дней, макс. размер=%d МБ",
        level_str, retention_days, max_size_mb,
    )


def reconfigure_logging(
    level: str = "INFO",
    retention_days: int = 30,
    max_size_mb: int = 50,
) -> None:
    """Переконфигурирует логирование (вызывается при сохранении настроек)."""
    setup_logging(level=level, retention_days=retention_days, max_size_mb=max_size_mb)


def _cleanup_old_logs(log_dir: str, retention_days: int) -> None:
    """Удаляет файлы логов старше retention_days."""
    cutoff = time.time() - (retention_days * 86400)
    try:
        for f in glob.glob(os.path.join(log_dir, "app.log.*")):
            try:
                if os.path.getmtime(f) < cutoff:
                    os.remove(f)
            except Exception:
                pass
    except Exception:
        pass


def get_log_dir() -> str:
    """Возвращает путь к директории логов."""
    return _LOG_DIR


def get_recent_log_files(max_files: int = 30) -> list[dict]:
    """Возвращает список файлов логов (для UI), отсортированных по дате (новые первые)."""
    log_dir = _ensure_log_dir()
    files: list[dict] = []

    # Текущий лог
    current = os.path.join(log_dir, "app.log")
    if os.path.isfile(current):
        stat = os.stat(current)
        files.append({
            "name": "app.log",
            "path": current,
            "size_kb": round(stat.st_size / 1024, 1),
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        })

    # Ротированные логи
    for f in sorted(glob.glob(os.path.join(log_dir, "app.log.*")), reverse=True):
        if len(files) >= max_files:
            break
        try:
            stat = os.stat(f)
            files.append({
                "name": os.path.basename(f),
                "path": f,
                "size_kb": round(stat.st_size / 1024, 1),
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            })
        except Exception:
            continue

    return files
