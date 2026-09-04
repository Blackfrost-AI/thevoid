"""Global settings for THE VOID's Frosty agent runtime."""

import os
import json
import logging
import copy
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
        self._data = {k: copy.deepcopy(v) for k, v in globals().items()
                      if k.isupper() and not k.startswith("_")}

    def get(self, key: str, default: Any = None) -> Any:
        """Get a setting value."""
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a setting value."""
        self._data[key] = value

    def load_file(self, path: str) -> None:
        """Validate the entire file before applying any of its settings."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as exc:
            raise ValueError(f"Cannot load configuration {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("Configuration must contain a JSON object.")
        for key, value in data.items():
            if key == "notes" and isinstance(value, str):
                continue
            if key not in self._data:
                raise ValueError(f"Unknown configuration setting: {key}")
            expected = self._data[key]
            if type(value) is not type(expected):
                raise ValueError(f"{key} must be {type(expected).__name__}.")
            if isinstance(expected, list) and expected and not all(
                type(item) is type(expected[0]) for item in value
            ):
                raise ValueError(f"{key} contains invalid list values.")
            if key in {"CLIENT_MODE", "REQUIRE_AUTHORIZATION", "DENY_HIGH_RISK_PHASES"} and value is not True:
                raise ValueError(f"{key} cannot be disabled in the client configuration.")
        self._data.update({k: v for k, v in data.items() if k != "notes"})

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
