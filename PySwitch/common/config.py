from typing import ClassVar

from .types import Env, BaseModel, Path
from pydantic import ConfigDict

import tomllib
import tomli_w

import logging
logger = logging.getLogger(__name__)

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


class Static(BaseModel):
    interface_count: int = 2
    processed_size: int = 1000

    @staticmethod
    def Get(filepath: Path) -> Static:
        return _from_toml(Static, filepath).Prepare()
    
    @staticmethod
    def Default() -> Static:
        return Static()
    
    def Prepare(self) -> Static:
        default = Static.Default()
        if (self.interface_count < 2 or self.interface_count > 32):
            logger.warning(f'Invalid value for "Static.interface_count", "{self.interface_count}" must be in range 2-32, using default {default.interface_count}')
            self.interface_count = default.interface_count
        if (self.processed_size < 1000 or self.processed_size > 1_000_000):
            logger.warning(f'Invalid value for "Static.processed_size", "{self.processed_size}" must be in range 1000-1000000, using default {default.processed_size}')
            self.processed_size = default.processed_size
        return self


class InterfaceSettings(BaseModel):
    name: str = "Unnamed port"
    number: int = 2000

class Live(BaseModel):
    interface_a: InterfaceSettings = InterfaceSettings()

    @staticmethod
    def Get(filepath: Path) -> Live:
        return _from_toml(Live, filepath).Prepare()

    def Save(self, filepath: Path) -> None:
        _write_toml(self, filepath)

    def Prepare(self) -> Live:
        return self

class Configuration(BaseModel):
    _instance: ClassVar[Configuration | None] = None

    env:    Env
    live:   Live
    static: Static

    @staticmethod
    def Get() -> Configuration:
        if Configuration._instance is not None:
            return Configuration._instance
        env = Env.Get()
        Configuration._instance = Configuration(
            env=env,
            live=Live.Get(env.config_directory / 'live.toml'),
            static=Static.Get(env.config_directory / 'static.toml'),
        )
        return Configuration._instance