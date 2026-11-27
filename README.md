# AI Fusion OS Pro

A standalone, governed AI workforce. It runs on its own and can optionally link to
[AI Fusion Engine Pro](https://github.com/7eeeshan/ai-fusion-engine-pro) for local model inference.

The upgrade is delivered in phases. Every phase ships only features with a working backend and tests.

| Phase | Scope | Status |
|---|---|---|
| 1 | Security controller, policy engine, sandboxed execution, approvals, audit log, budgets, emergency stop, untrusted-content handling, optional engine link | Done |
| 2 | Memory (semantic, episodic, procedural, knowledge graph, retrieval) with provenance and poisoning checks; experience learning; skill manager | **This release** |
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

## Phase 2: memory, learning and skills

**Memory** (`fusion_os/memory`, SQLite): semantic facts, episodic mission history, procedural know-how and a
knowledge graph (subject, predicate, object). Retrieval is BM25 full-text ranking, blended with vector similarity
when an embedding function is supplied, and weighted by trust. Every record keeps its source, source type, agent,
mission and content hash.

Poisoning defences: trust levels `verified` > `user` > `agent` > `external`. Agents can't write `verified`; only the
admin can promote. External or agent content that trips the injection scan is quarantined and never retrieved until
the admin releases it. External memories always come back wrapped as untrusted data. Duplicates are ignored, and
retracted records stay for audit. Every write and read goes through the security gate, so the dark-web zone can't
write memory.

**Learning from experience**: each mission outcome is recorded. A success becomes a reusable procedure. A failure is
kept with its error, and when it's resolved the fix becomes a procedure too. `lessons(goal)` returns what worked
and what failed for similar goals, and `failure_patterns()` lists recurring unresolved errors.

This phase covers knowledge acquisition and workflow reuse. Prompt optimisation and model fine-tuning are separate
and come in Phase 6.

**Skills** (`fusion_os/skills`): a skill is a folder with `skill.json`, an entrypoint and tests (see
`examples/skills/text-stats`). Submitting one triggers automatic validation:
- manifest and licence allowlist (MIT, Apache-2.0, BSD, ISC, MPL-2.0, ...);
- a file check (relative paths only, allowed file types, under 1 MB, no symlinks);
- AST static analysis (no subprocess, ctypes, pickle, eval/exec, os.system, dunder tricks; no network modules
  unless the manifest asks for network);
- a dependency check (standard library only for now);
- the skill's own tests and an example run, both in the Docker sandbox with no network.

Only validated skills can be registered, and registration needs a human approval bound to the skill's content hash.
Active skills run for any agent allowed `skill.execute`, always in the sandbox. A skill whose files change after
approval refuses to run. Versions are kept, and `rollback` restores the previous one. `GET /v1/skills/match`
reports a capability gap when no active skill covers a need.

Verified live here: the example skill passes validation in the sandbox, waits for approval, runs after approval,
upgrades to 1.1.0 and rolls back to 1.0.0, and a tampered skill is blocked.

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

## API

Agent token: `POST /v1/authorize`, `POST /v1/sandbox/exec`, `POST /v1/untrusted/scan`, `GET /v1/approvals/{id}`,
`POST /v1/memory`, `GET /v1/memory/search`, `GET /v1/memory/graph`, `POST /v1/episodes[/{id}/resolve]`, `GET /v1/lessons`,
`GET /v1/skills`, `GET /v1/skills/match`, `POST /v1/skills/submit`, `POST /v1/skills/{name}/{version}/register`, `POST /v1/skills/{name}/run`.
Admin token: `/admin/status`, `/admin/approvals[/{id}]`, `/admin/audit[/verify]`, `/admin/engagements`,
`/admin/agents`, `/admin/budgets/{mission}`, `/admin/memory[/{id}/release|retract|promote]`, `/admin/skills/{name}/rollback`, `/admin/policy`, `/admin/emergency-stop`, `/admin/resume`, `/admin/engine`.

## Limits of Phase 1 (honest list)

- The controller runs in the same process as the API; separating it into its own OS service with its own account
  comes with the mission runner in Phase 3.
- The admin token sits in a 0600 file; moving it to Windows Credential Manager is planned.
- Prompt-injection detection is pattern-based and will miss novel attacks. It is one layer: the real protection is
  that external content can never change policy, approvals or permissions.
- No security tools, research engines or dashboard yet. Those are later phases.
- Skills can't use third-party packages yet. That needs a vetted, offline wheel cache, which comes with Phase 4.
- Searching skills on the internet and drafting new ones automatically comes with the mission runner in Phase 3.
  Phase 2 provides the validate, approve, register and run pipeline those drafts will go through.
