from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Settings:
    policy_path: Path
    database_path: Path
    hexstrike_url: str
    api_key: str | None
    auth_disabled: bool = False
    require_separate_approver: bool = True
    request_timeout_seconds: float = 120.0

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            policy_path=Path(
                os.getenv(
                    "CONTROL_PLANE_POLICY_PATH",
                    str(Path(__file__).resolve().parents[1] / "control-plane-policy.json"),
                )
            ),
            database_path=Path(os.getenv("CONTROL_PLANE_DATABASE_PATH", "data/control-plane.db")),
            hexstrike_url=os.getenv("HEXSTRIKE_URL", "http://127.0.0.1:8888").rstrip("/"),
            api_key=os.getenv("CONTROL_PLANE_API_KEY"),
            auth_disabled=os.getenv("CONTROL_PLANE_AUTH_DISABLED", "false").lower() == "true",
            require_separate_approver=os.getenv(
                "CONTROL_PLANE_REQUIRE_SEPARATE_APPROVER", "true"
            ).lower()
            == "true",
            request_timeout_seconds=float(os.getenv("CONTROL_PLANE_REQUEST_TIMEOUT", "120")),
        )


def load_policy(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(f"Policy file not found: {path}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON policy at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Policy root must be a JSON object")
    return data

