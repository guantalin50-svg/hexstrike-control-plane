from __future__ import annotations

from typing import Any, Protocol

import httpx

from .models import JobRecord


class Executor(Protocol):
    def execute(self, job: JobRecord) -> Any: ...


class HexStrikeExecutor:
    TARGET_FIELDS = {
        "dirsearch": "url",
        "feroxbuster": "url",
        "ffuf": "url",
        "gobuster": "url",
        "sqlmap": "url",
    }

    def __init__(self, base_url: str, timeout_seconds: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def execute(self, job: JobRecord) -> Any:
        payload = dict(job.arguments)
        target_field = self.TARGET_FIELDS.get(job.tool, "target")
        payload[target_field] = job.target
        if job.dry_run:
            return {
                "dry_run": True,
                "method": "POST",
                "url": f"{self.base_url}/api/tools/{job.tool}",
                "payload": payload,
            }

        with httpx.Client(
            timeout=self.timeout_seconds,
            follow_redirects=False,
        ) as client:
            response = client.post(f"{self.base_url}/api/tools/{job.tool}", json=payload)
            response.raise_for_status()
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                return response.json()
            return {"status_code": response.status_code, "body": response.text[:1_000_000]}

