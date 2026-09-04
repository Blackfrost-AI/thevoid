"""Global settings for THE VOID's Frosty agent runtime."""

import os
import json
import logging
from typing import Any, Optional
from .defaults import *


class Settings:
    """Singleton settings container that can be loaded from file or environment."""

    _instance: Optional["Settings"] = None
    _data: dict = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_defaults()
        return cls._instance

    def _load_defaults(self) -> None:
        """Load all defaults into settings."""
        self._data = {k: v for k, v in globals().items()
                      if k.isupper() and not k.startswith("_")}

    def get(self, key: str, default: Any = None) -> Any:
        """Get a setting value."""
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a setting value."""
        self._data[key] = value

    def load_file(self, path: str) -> None:
        """Load settings from a JSON file."""
        if os.path.exists(path):
            with open(path, "r") as f:
                data = json.load(f)
                for k, v in data.items():
                    self._data[k] = v

    def save_file(self, path: str) -> None:
        """Save current settings to a JSON file."""
        with open(path, "w") as f:
            json.dump(self._data, f, indent=2, default=str)

    def to_dict(self) -> dict:
        """Return settings as a dictionary."""
        return dict(self._data)

    def __repr__(self) -> str:
        return f"Settings({len(self._data)} keys)"


def get_settings() -> Settings:
    """Get the global settings singleton."""
    return Settings()
