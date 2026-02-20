from pathlib import Path
from typing import ClassVar, Optional

from pydantic import BaseModel
from dataclasses import dataclass  # kept for re-export

import logging
logger = logging.getLogger(__name__)


class Env(BaseModel):
    _instance: ClassVar[Env | None] = None

    config_directory: Path = Path("data")

    @staticmethod
    def Get() -> Env:
        if Env._instance is not None:
            return Env._instance
        import dotenv
        env_filepath = dotenv.find_dotenv()
        if env_filepath == '' or not Path(env_filepath).exists():
            logger.warning("No .env file found, using defaults")
        values = dotenv.dotenv_values()
        Env._instance = Env.model_validate(values).Prepare()
        return Env._instance

    def Prepare(self) -> Env:
        self.config_directory.mkdir(parents=True, exist_ok=True)
        return self