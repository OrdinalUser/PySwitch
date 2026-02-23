from __future__ import annotations

import os
import threading
from typing import ClassVar, Callable

from .types import Env, BaseModel, Path
from pydantic import ConfigDict, PrivateAttr

import tomllib
import tomli_w

import logging
logger = logging.getLogger(__name__)

from watchdog.events import FileModifiedEvent, FileSystemEventHandler
from watchdog.observers import Observer


# ── TOML helpers ──────────────────────────────────────────────────────────────

def _load_toml(filepath: Path) -> dict:
    with open(filepath, "rb") as f:
        return tomllib.load(f)

def _write_toml(instance: BaseModel, filepath: Path) -> None:
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "wb") as f:
        tomli_w.dump(instance.model_dump(), f)

def _from_toml(cls: type, filepath: Path):
    """Load a Pydantic model from TOML. Creates the file with defaults if missing."""
    if not filepath.exists():
        logger.info("Creating default %s config at %s", cls.__name__, filepath.resolve())
        default = cls()
        _write_toml(default, filepath)
        return default
    logger.debug("Loading %s config from %s", cls.__name__, filepath.resolve())
    return cls.model_validate(_load_toml(filepath))


# ── Live file watcher ─────────────────────────────────────────────────────────

_live_reload_lock = threading.Lock()

class _LiveFileHandler(FileSystemEventHandler):
    """Watchdog handler — debounces rapid save events and fires on_reload."""

    _DEBOUNCE_S = 0.3  # editors often fire 2-3 events per save

    def __init__(self, filepath: Path, on_reload: Callable):
        super().__init__()
        self._filepath     = filepath.resolve()
        self._on_reload    = on_reload
        self._debounce_lock = threading.Lock()
        self._last_t       = 0.0

    def on_modified(self, event) -> None:
        if not isinstance(event, FileModifiedEvent):
            return
        if Path(os.fsdecode(event.src_path)).resolve() != self._filepath:
            return

        import time
        now = time.monotonic()
        with self._debounce_lock:
            if now - self._last_t < self._DEBOUNCE_S:
                return
            self._last_t = now

        try:
            new_live = _from_toml(Live, self._filepath).Prepare()
        except Exception as exc:
            logger.warning("Live config reload failed, keeping current: %s", exc)
            return

        with _live_reload_lock:
            self._on_reload(new_live)

        logger.info("Live config hot-reloaded from %s", self._filepath)


# ── Settings models ───────────────────────────────────────────────────────────

class UI(BaseModel):
    refresh_rate_ms: int = 1000
    log_drain_ms: int = 1000

class Core(BaseModel):
    interface_count: int = 2
    inteface_buffer: int = 256
    interface_drain_s: float = 0.05

class Metrics(BaseModel):
    throughput_buffer_size: int = 1000

class Static(BaseModel):
    ui: UI = UI()
    core: Core = Core()
    metrics: Metrics = Metrics()

    @staticmethod
    def Get(filepath: Path) -> Static:
        return _from_toml(Static, filepath).Prepare()

    @staticmethod
    def Default() -> Static:
        return Static()

    def Prepare(self) -> Static:
        default = Static.Default()
        if (self.core.interface_count < 2 or self.core.interface_count > 32):
            logger.warning(f'Invalid value for "Static.interface_count", "{self.core.interface_count}" must be in range 2-32, using default {default.core.interface_count}')
            self.interface_count = default.core.interface_count
        if (self.metrics.throughput_buffer_size < 1000 or self.metrics.throughput_buffer_size > 1_000_000):
            logger.warning(f'Invalid value for "Static.processed_size", "{self.metrics.throughput_buffer_size}" must be in range 1000-1000000, using default {default.processed_size}')
            self.metrics.throughput_buffer_size = default.metrics.throughput_buffer_size
        return self


class CoreLive(BaseModel):
    mac_expiry_s: int = 300
    cleanup_thread_sleep_s: int = 15
    core_thread_sleep_s: int = 3

class Live(BaseModel):
    core: CoreLive = CoreLive()
    # ClassVar keeps the watching instance alive across configuration swaps.
    # When Configuration.live is replaced with a fresh Live, the old watcher
    # instance would otherwise be GC'd and the observer would stop.
    _watching: ClassVar[Live | None] = None

    # PrivateAttr: Pydantic ignores these for validation and serialization
    _observer: Observer | None  = PrivateAttr(default=None)
    _filepath:  Path | None     = PrivateAttr(default=None)
    _on_reload: Callable | None = PrivateAttr(default=None)

    @staticmethod
    def Get(filepath: Path) -> Live:
        live = _from_toml(Live, filepath).Prepare()
        live._filepath = filepath
        return live

    def Save(self, filepath: Path) -> None:
        _write_toml(self, filepath)

    def Prepare(self) -> Live:
        return self

    def Watch(self, on_reload: Callable[[Live], None]) -> Live:
        """Start watching the config file. Keeps this instance alive via _watching."""
        if self._observer is not None:
            return self
        assert self._filepath is not None, "Watch() called on a Live not created via Get()"

        self._on_reload = on_reload
        Live._watching  = self  # prevent GC when Configuration.live is swapped

        handler = _LiveFileHandler(self._filepath, on_reload)
        obs = Observer()
        obs.schedule(handler, str(self._filepath.parent), recursive=False)
        obs.daemon = True
        obs.start()
        self._observer = obs
        logger.debug("Live config watch started on %s", self._filepath.resolve())
        return self

    def StopWatch(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join()
            self._observer = None
            logger.info("Live config watch stopped")
        if Live._watching is self:
            Live._watching = None

    def __del__(self) -> None:
        # Only the watcher instance has an observer; plain reloaded instances are no-ops.
        if self._observer is not None:
            self._observer.stop()

    def __enter__(self) -> Live:
        # Pins this instance for the duration of the block.
        # Even if Configuration.live is swapped by the watcher thread mid-read,
        # this reference stays valid and consistent.
        return self

    def __exit__(self, *_) -> None:
        pass  # ref count handles cleanup


# ── Configuration singleton ───────────────────────────────────────────────────

class Configuration(BaseModel):
    _instance: ClassVar[Configuration | None] = None

    env:    Env
    live:   Live
    static: Static

    @staticmethod
    def Get() -> Configuration:
        if Configuration._instance is not None:
            return Configuration._instance
        env  = Env.Get()
        live = Live.Get(env.config_directory / 'live.toml')
        live.Watch(lambda new: setattr(Configuration._instance, 'live', new))
        Configuration._instance = Configuration(
            env=env,
            live=live,
            static=Static.Get(env.config_directory / 'static.toml'),
        )
        return Configuration._instance
