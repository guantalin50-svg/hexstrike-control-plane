# HexStrike Control Plane

HexStrike Control Plane is an opt-in safety gateway in front of the existing HexStrike server. It makes tool execution explicit, policy-controlled, attributable, and auditable without changing the upstream HexStrike core.

> Use security tooling only on systems you own or have explicit permission to test.

## What it provides

- Fail-closed target and tool policies
- Human approval for elevated tools
- Separation of requester and approver identities by default
- API-key protection with constant-time comparison
- Dry-run previews before requests reach HexStrike
- Persistent job state in SQLite
- Hash-chained audit events with integrity verification
- A restricted adapter that only forwards `/api/tools/{tool}` requests
- Per-tool argument allowlists that reject unvalidated shell-bound values
- Local-only Docker port binding and an internal Docker network

The gateway intentionally does not expose HexStrike's raw command, arbitrary Python, payload-generation, or exploit-generation endpoints.

## Quick start

Python 3.10 or newer is required.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-control-plane.txt

export CONTROL_PLANE_API_KEY="replace-with-a-long-random-value"
export HEXSTRIKE_URL="http://127.0.0.1:8888"
uvicorn control_plane.app:app --host 127.0.0.1 --port 8890
```

On PowerShell, use `$env:CONTROL_PLANE_API_KEY = "..."` instead of `export`.

Open `http://127.0.0.1:8890/docs` for the interactive API documentation.

### Docker Compose

Start HexStrike on port 8888 first. The compose service connects to it through `host.docker.internal` by default and exposes the Control Plane only on local loopback.

```bash
export CONTROL_PLANE_API_KEY="replace-with-a-long-random-value"
docker compose -f docker-compose.control-plane.yml up --build
```

## Configure authorization policy

Edit `control-plane-policy.json` before use. The shipped policy permits only loopback and reserved test domains. Unknown tools and out-of-scope targets are denied.

Wildcard domain rules match the normalized hostname. CIDR rules are supported for IPv4 and IPv6.

```json
{
  "targets": {
    "allow": ["staging.example.com", "10.20.0.0/24"],
    "deny": ["prod.example.com"]
  },
  "tools": {
    "allow": ["nmap", "nuclei"],
    "require_approval": ["nikto", "sqlmap"],
    "deny": ["hydra", "metasploit"],
    "default": "deny"
  },
  "parameters": {
    "nmap": ["scan_type", "ports", "use_recovery"],
    "nuclei": ["severity", "tags", "use_recovery"]
  }
}
```

## API workflow

Set two headers on protected endpoints:

- `X-Control-Plane-Key`: the configured API key
- `X-Actor`: a human or service identity used in the audit record

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

Execute an allowed or approved job:

```bash
curl -X POST http://127.0.0.1:8890/v1/jobs/JOB_ID/run \
  -H "X-Control-Plane-Key: $CONTROL_PLANE_API_KEY" \
  -H "X-Actor: security-engineer@example.com"
```

Elevated tools first return `pending_approval`. Approve them with a separate accountable identity:

```bash
curl -X POST http://127.0.0.1:8890/v1/jobs/JOB_ID/approve \
  -H "Content-Type: application/json" \
  -H "X-Control-Plane-Key: $CONTROL_PLANE_API_KEY" \
  -H "X-Actor: security-lead@example.com" \
  -d '{"reason":"Approved staging assessment ticket SEC-123"}'
```

Verify that the append-only audit hash chain has not been altered:

```bash
curl http://127.0.0.1:8890/v1/audit/verify \
  -H "X-Control-Plane-Key: $CONTROL_PLANE_API_KEY"
```

## Security boundaries

This first release is a policy and audit boundary, not a complete sandbox. It rejects target fields hidden inside `arguments`, overwrites the upstream target field, and accepts only explicitly validated parameters. Run HexStrike in a dedicated container or virtual machine with restricted network access. Do not expose either service directly to the public internet. A production deployment should add TLS, an external identity provider, role-based approval separation, secret storage, and container-level egress controls.

