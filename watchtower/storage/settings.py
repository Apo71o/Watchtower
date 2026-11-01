"""Key/value settings persisted in SQLite (values stored as JSON)."""

from __future__ import annotations

import json
from typing import Any

from watchtower.storage.db import Database

# Well-known keys
DEPS_REVIEWED = "dependency_check_seen"  # bool
NVD_API_KEY = "nvd_api_key"
NVD_ENABLED = "nvd_lookups_enabled"      # bool, default False (no network calls)
THEME = "theme"                          # "system" | "light" | "dark"


class Settings:
    def __init__(self, db: Database):
        self.db = db

    def get(self, key: str, default: Any = None) -> Any:
        rows = self.db.query("SELECT value FROM settings WHERE key = ?", (key,))
        return json.loads(rows[0]["value"]) if rows else default

    def set(self, key: str, value: Any) -> None:
        self.db.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value)),
        )

    def delete(self, key: str) -> None:
        self.db.execute("DELETE FROM settings WHERE key = ?", (key,))
