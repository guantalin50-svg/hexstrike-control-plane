# Security policy

HexStrike and the optional Control Plane are intended only for systems you own or are explicitly authorized to test.

## Safe deployment

- Keep both services on a private network.
- Set a long, random `CONTROL_PLANE_API_KEY` and store it outside the repository.
- Replace the example target policy before running real assessments.
- Run HexStrike in a dedicated container or virtual machine with restricted egress.
- Keep the default fail-closed tool policy and add capabilities deliberately.
- Use separate requester and approver identities for elevated jobs.
- Back up the SQLite audit database to append-only storage.

The Control Plane does not expose HexStrike's raw command, arbitrary Python, payload-generation, or exploit-generation endpoints. Do not add these endpoints without an independent authentication, authorization, sandboxing, and security review.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue. Contact the repository owner privately through their GitHub profile and include reproduction steps, affected versions, impact, and any suggested mitigation. Avoid accessing data or systems beyond what is necessary to demonstrate the issue.

