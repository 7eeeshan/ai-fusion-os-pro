# AI Fusion OS Pro

A standalone, governed AI workforce. It runs on its own and can optionally link to
[AI Fusion Engine Pro](https://github.com/7eeeshan/ai-fusion-engine-pro) for local model inference.

The upgrade is delivered in phases. Every phase ships only features with a working backend and tests.

| Phase | Scope | Status |
|---|---|---|
| 1 | Security controller, policy engine, sandboxed execution, approvals, audit log, budgets, emergency stop, untrusted-content handling, optional engine link | **This release** |
| 2 | Memory (semantic, episodic, procedural, knowledge graph, RAG) with provenance and poisoning checks; skill manager | Next |
| 3 | Mission runner and multi-agent coordination (bounded teams, loop and resource limits, independent verification) | Planned |
| 4 | Cybersecurity division: permission-controlled tool adapters (Nmap, ZAP, Nuclei, Semgrep, Trivy, YARA, ...) running in the sandbox, OWASP/ATT&CK-mapped reports | Planned |
| 5 | Research engines: surface web, authorized portals, isolated Tor zone | Planned |
| 6 | Technology intelligence, model benchmarking and upgrades with rollback, self-healing | Planned |
| 7 | Cloud worker and queues; dashboard | Planned |

## Phase 1: what it does

Every agent action goes through one gate, `SecurityController.authorize()`, in this order:

1. **Emergency stop**: if active, everything is denied.
2. **Identity and zone**: agents hold their own token, bound to an agent id and zones (`standard`, `research`,
   `security`, `darkweb`). A dark-web identity can hold no other zone.
3. **Policy**: immutable rules in code run first and cannot be weakened by the policy file (no policy changes by
   agents; dark-web zone cut off from credentials, files, security tools, sandbox, memory writes; Tor only from the
   dark-web zone; purchases, credential theft, phishing, DDoS and malware building always denied). Then the JSON
   policy, first match wins, default deny. The policy file is pinned by SHA-256; if it is edited outside the admin
   path, the controller fails closed.
4. **Engagement scope** for active security testing: an engagement records who authorized it and the reference
   (SOW, letter, ticket), the target allowlist (IPs, CIDRs up to /16, hostnames, `*.domain`), exclusions, allowed
   tools, time window (max 90 days) and a request budget.
5. **Mission budget**: calls, compute seconds and money per mission.
6. **Human approval** for privileged actions (skill registration, model install, system update, agent spawn,
   credential read, file writes, networked sandbox runs, exploit verification). Approvals are single-use, expire,
   and are bound to a hash of the exact request.

Every decision is written to a **hash-chained, append-only audit log** (SQLite triggers block edits; `verify`
detects any tampering). Secrets in parameters are redacted.

**Sandbox**: commands run in Docker with no network by default, read-only root, all capabilities dropped,
no-new-privileges, uid 65534, PID/memory/CPU limits and a timeout. Only allowlisted images run. If Docker is not
available it refuses; it never falls back to the host. Verified live: the container runs as 65534, cannot write
its filesystem, has no network, is killed on timeout and gets the memory limit.

**Untrusted content**: external text is wrapped with provenance and a random boundary the content cannot fake, and
scanned for prompt-injection patterns (instruction override, role hijack, fake system tags, exfiltration requests,
tool coercion, attempts to disable safety, hidden Unicode).

**Engine link**: if AI Fusion Engine Pro is running (`AFE_URL`, `AFE_TOKEN`), status, models and chat go through its
API. If not, it reports itself as disconnected.

## Run

```powershell
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"
.venv\Scripts\python -m pytest -q
.venv\Scripts\python -m fusion_os serve          # API on http://127.0.0.1:8790 (docs at /docs)
.venv\Scripts\python -m fusion_os admin-token    # your admin token
.venv\Scripts\python -m fusion_os add-agent researcher research
```

Docker Desktop is needed for the sandbox. Data lives in `%LOCALAPPDATA%\AIFusionOSPro` (override with `FUSION_OS_HOME`).

## API (Phase 1)

Agent token: `POST /v1/authorize`, `POST /v1/sandbox/exec`, `POST /v1/untrusted/scan`, `GET /v1/approvals/{id}`.
Admin token: `/admin/status`, `/admin/approvals[/{id}]`, `/admin/audit[/verify]`, `/admin/engagements`,
`/admin/agents`, `/admin/budgets/{mission}`, `/admin/policy`, `/admin/emergency-stop`, `/admin/resume`, `/admin/engine`.

## Limits of Phase 1 (honest list)

- The controller runs in the same process as the API; separating it into its own OS service with its own account
  comes with the mission runner in Phase 3.
- The admin token sits in a 0600 file; moving it to Windows Credential Manager is planned.
- Prompt-injection detection is pattern-based and will miss novel attacks. It is one layer: the real protection is
  that external content can never change policy, approvals or permissions.
- No security tools, research engines, memory or dashboard yet. Those are later phases.
