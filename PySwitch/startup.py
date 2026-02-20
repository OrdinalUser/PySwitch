import ctypes
import logging
import queue
import sys
from pathlib import Path


_mutex = None  # keep reference alive for process lifetime
_log_queue: queue.SimpleQueue = queue.SimpleQueue()


class _QueueHandler(logging.Handler):
    """Feeds formatted log records into _log_queue for the GUI to drain."""
    def emit(self, record: logging.LogRecord) -> None:
        _log_queue.put_nowait(self.format(record))


def get_log_queue() -> queue.SimpleQueue:
    return _log_queue


def ensure_singleton() -> None:
    """Prevent more than one instance from running. Exits immediately if another is found."""
    global _mutex
    _mutex = ctypes.windll.kernel32.CreateMutexW(None, True, "Global\\PySwitch_NetworkSwitch")
    if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        ctypes.windll.user32.MessageBoxW(
            0,
            "PySwitch is already running.",
            "PySwitch",
            0x10,  # MB_ICONERROR
        )
        sys.exit(1)


def setup_logging(log_file: Path | None = None) -> None:
    """Configure root logger. Call once at startup before anything else."""
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG)
    console.setFormatter(fmt)
    root.addHandler(console)

    queue_handler = _QueueHandler()
    queue_handler.setLevel(logging.DEBUG)
    queue_handler.setFormatter(fmt)
    root.addHandler(queue_handler)

    if log_file is not None:
        add_file_handler(log_file)


def add_file_handler(log_file: Path) -> None:
    """Add a file handler to the root logger after Env is available."""
    root = logging.getLogger()
    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    log_file.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)