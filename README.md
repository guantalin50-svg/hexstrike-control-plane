# HexStrike Control Plane

An experimental, policy-controlled safety gateway for authorized HexStrike AI security workflows.

HexStrike Control Plane sits between an AI client and a HexStrike server. It checks the requested target and tool, pauses elevated actions for approval, forwards only validated requests, and keeps a tamper-evident audit history.

> Use security tooling only on systems you own or have explicit permission to assess.

This is an independent community project compatible with [HexStrike AI](https://github.com/0x4m4/hexstrike-ai). It is not an official component of the upstream project.

## Why it exists

Connecting an AI agent directly to offensive-security tooling creates practical risks: out-of-scope targets, unsafe parameters, accidental duplicate execution, and missing accountability. This project adds a fail-closed control boundary without modifying HexStrike's core server.

```text
AI client or operator
        │
        ▼
HexStrike Control Plane
  ├─ API-key authentication
  ├─ target scope policy
  ├─ tool and parameter policy
  ├─ human approval
  ├─ job state and concurrency control
  └─ hash-chained audit events
        │ approved requests only
        ▼
HexStrike server
```

## Features

- Target allowlists and explicit deny rules for domains, IP addresses, and CIDRs
- Per-tool `allow`, `require_approval`, and `deny` decisions
- Strict argument allowlists and value validation
- Protection against target-field smuggling and shell-bound parameter injection
- Separate requester and approver identities for elevated jobs
- Dry-run previews
- API-key authentication using constant-time comparison
- SQLite job persistence with atomic state transitions
- Hash-chained audit records with integrity verification
- Restricted forwarding to `/api/tools/{tool}` only
- FastAPI/OpenAPI documentation, Docker packaging, and GitHub Actions tests

The gateway intentionally does **not** expose HexStrike's raw command, arbitrary Python, payload-generation, or exploit-generation endpoints.

## Quick start

Python 3.10 or newer is required. Start a HexStrike server on port `8888`, then run:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-control-plane.txt

export CONTROL_PLANE_API_KEY="replace-with-a-long-random-value"
export HEXSTRIKE_URL="http://127.0.0.1:8888"
uvicorn control_plane.app:app --host 127.0.0.1 --port 8890
```

PowerShell equivalent:

```powershell
.venv\Scripts\Activate.ps1
$env:CONTROL_PLANE_API_KEY = "replace-with-a-long-random-value"
$env:HEXSTRIKE_URL = "http://127.0.0.1:8888"
uvicorn control_plane.app:app --host 127.0.0.1 --port 8890
```

Open `http://127.0.0.1:8890/docs` for the interactive API documentation.

The example policy permits only loopback and reserved test domains. Edit `control-plane-policy.json` before using real authorized targets.

## Example workflow

Create a dry-run job:

```bash
curl -X POST http://127.0.0.1:8890/v1/jobs \
  -H "Content-Type: application/json" \
  -H "X-Control-Plane-Key: $CONTROL_PLANE_API_KEY" \
  -H "X-Actor: security-engineer@example.com" \
  -d '{
    "tool": "nmap",
    "target": "service.test",
    "arguments": {"ports": "80,443"},
    "justification": "Validate the staging exposure before release",
    "dry_run": true
  }'
```

Jobs using elevated tools remain in `pending_approval` until a different actor approves them. Allowed or approved jobs can then be submitted to `POST /v1/jobs/{job_id}/run`.

## Documentation

- [Setup, policy, and API guide](docs/CONTROL_PLANE.md)
- [Security policy and deployment guidance](SECURITY.md)
- [Example authorization policy](control-plane-policy.json)

## Development

```bash
pip install -r requirements-control-plane-dev.txt
pytest -q
python -m compileall -q control_plane
```

The current test suite covers policy decisions, target normalization, injection attempts, approval separation, API authentication, atomic job claiming, and audit-chain verification.

## Current boundary

Version `0.1.0` is a policy, approval, and audit boundary—not a complete security sandbox. Run the downstream HexStrike server in a dedicated container or virtual machine with restricted network access. Do not expose either service directly to the public internet.

## License

MIT — see [LICENSE](LICENSE).


