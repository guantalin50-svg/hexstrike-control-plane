import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from control_plane.app import create_app
from control_plane.config import Settings
from control_plane.models import JobRecord


class FakeExecutor:
    def execute(self, job: JobRecord) -> Any:
        return {"tool": job.tool, "target": job.target, "executed": True}


def make_client(tmp_path: Path) -> TestClient:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "targets": {"allow": ["*.test"], "deny": ["blocked.test"]},
                "tools": {
                    "allow": ["nmap"],
                    "require_approval": ["nikto"],
                    "deny": ["hydra"],
                    "default": "deny",
                },
                "parameters": {"nmap": ["ports"], "nikto": [], "hydra": []},
            }
        ),
        encoding="utf-8",
    )
    settings = Settings(
        policy_path=policy_path,
        database_path=tmp_path / "control-plane.db",
        hexstrike_url="http://127.0.0.1:8888",
        api_key="test-key",
    )
    return TestClient(create_app(settings, executor=FakeExecutor()))


HEADERS = {"X-Control-Plane-Key": "test-key", "X-Actor": "tester"}


def test_rejects_missing_api_key(tmp_path: Path):
    response = make_client(tmp_path).get("/v1/jobs")
    assert response.status_code == 401


def test_allowed_job_executes_and_is_audited(tmp_path: Path):
    client = make_client(tmp_path)
    response = client.post(
        "/v1/jobs",
        headers=HEADERS,
        json={
            "tool": "nmap",
            "target": "api.test",
            "arguments": {"ports": "443"},
            "justification": "authorized staging check",
        },
    )
    assert response.status_code == 201
    job = response.json()
    assert job["status"] == "ready"

    completed = client.post(f"/v1/jobs/{job['id']}/run", headers=HEADERS)
    assert completed.status_code == 200
    assert completed.json()["status"] == "succeeded"
    assert completed.json()["result"]["executed"] is True

    audit = client.get("/v1/audit", headers=HEADERS)
    assert {event["action"] for event in audit.json()} == {
        "job.created",
        "job.started",
        "job.succeeded",
    }
    assert client.get("/v1/audit/verify", headers=HEADERS).json() == {"valid": True}


def test_elevated_job_cannot_run_until_approved(tmp_path: Path):
    client = make_client(tmp_path)
    created = client.post(
        "/v1/jobs",
        headers=HEADERS,
        json={
            "tool": "nikto",
            "target": "api.test",
            "justification": "approved web assessment",
        },
    ).json()
    assert created["status"] == "pending_approval"
    assert client.post(f"/v1/jobs/{created['id']}/run", headers=HEADERS).status_code == 409

    approved = client.post(
        f"/v1/jobs/{created['id']}/approve",
        headers={**HEADERS, "X-Actor": "security-lead"},
        json={"reason": "ticket SEC-123"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"


def test_requester_cannot_self_approve(tmp_path: Path):
    client = make_client(tmp_path)
    created = client.post(
        "/v1/jobs",
        headers=HEADERS,
        json={
            "tool": "nikto",
            "target": "api.test",
            "justification": "approved web assessment",
        },
    ).json()
    response = client.post(
        f"/v1/jobs/{created['id']}/approve",
        headers=HEADERS,
        json={"reason": "self approval should fail"},
    )
    assert response.status_code == 409


def test_out_of_scope_job_is_denied(tmp_path: Path):
    response = make_client(tmp_path).post(
        "/v1/jobs",
        headers=HEADERS,
        json={
            "tool": "nmap",
            "target": "example.com",
            "justification": "should not be allowed",
        },
    )
    assert response.status_code == 201
    assert response.json()["status"] == "denied"


def test_rejects_target_smuggling_in_arguments(tmp_path: Path):
    response = make_client(tmp_path).post(
        "/v1/jobs",
        headers=HEADERS,
        json={
            "tool": "nmap",
            "target": "api.test",
            "arguments": {"target": "example.com"},
            "justification": "attempted policy bypass",
        },
    )
    assert response.status_code == 422


def test_unvalidated_shell_arguments_are_denied(tmp_path: Path):
    response = make_client(tmp_path).post(
        "/v1/jobs",
        headers=HEADERS,
        json={
            "tool": "nmap",
            "target": "api.test",
            "arguments": {"additional_args": "; whoami"},
            "justification": "attempted command injection",
        },
    )
    assert response.status_code == 201
    assert response.json()["status"] == "denied"

