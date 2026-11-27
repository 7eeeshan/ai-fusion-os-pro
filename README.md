# AI Fusion OS Pro

A standalone, governed AI workforce. It runs on its own and can optionally link to
[AI Fusion Engine Pro](https://github.com/7eeeshan/ai-fusion-engine-pro) for local model inference.

The upgrade is delivered in phases. Every phase ships only features with a working backend and tests.

| Phase | Scope | Status |
|---|---|---|
| 1 | Security controller, policy engine, sandbox, approvals, audit log, budgets, emergency stop, untrusted content | Done |
| 2 | Memory with provenance and poisoning checks, learning from experience, skill manager | Done |
| 3 | Mission runner: bounded multi-agent teams, plan experiments, verification, replanning, skill-gap acquisition | Done |
| 4 | Cybersecurity division: sandboxed tool adapters, engagement-scoped testing, findings, verification, reports, IDS ingest | Done |
| 5 | Research: guarded web fetch, search, arXiv, approved portal access, isolated Tor zone, evidence stores | Done |
| 6 | Technology intelligence, model benchmarking and approved upgrades with rollback, health, self-healing, backups, improvement lab | Done |
| 7 | Cloud queue and workers (local/cloud hand-over without duplicates), scheduler, Docker deployment, mission control dashboard | Done |
| 8 | Windows desktop app: Tauri 2 shell, setup.exe and MSI, bundled Python and Tor, no Docker required, tray, start at sign-in, crash recovery | Milestone 1 done ([docs/desktop.md](docs/desktop.md)) |

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

## Phase 3: missions and multi-agent reasoning

`POST /admin/missions {"goal": ...}` starts a mission. The planner drafts several candidate plans; a critic scores
them against lessons from past missions; a dry run rejects plans with unknown tools, too many steps or roles, or
actions the policy would deny. Each step runs as a role agent with its own short-lived identity through the security
gate, and an independent verifier checks every result. Failed steps trigger reflection and a revised plan (at most
`max_replans`). Limits: steps, replans, team size, wall time and a per-mission budget that every model call is
charged against. Missions can't start missions. When a plan needs a capability nobody has, the model drafts a skill,
which goes through sandbox validation and waits for your approval; the mission resumes after it. Outcomes become
episodes, so the next similar mission sees what worked and what failed.

Models: AI Fusion Engine Pro, your PC's engine through the queue, then Anthropic, tried in `FUSION_OS_LLM_ORDER`
order with automatic fallback. With no model available a mission is marked `blocked`, never simulated.

## Phase 4: cybersecurity division

Adapters for Nmap, Nuclei, Semgrep, Trivy and YARA, each running in a
pinned container image in the sandbox. Active testing is refused unless the target is inside an engagement's
allowlist, not excluded, inside its time window, with an authorized tool and within its request budget. Findings are
de-duplicated, mapped to OWASP and MITRE ATT&CK, carry evidence and remediation, and are tracked through
open, verified, fixed, false positive and accepted risk. Verification re-tests need approval. Reports (Markdown)
include scope and authorization, methodology, severity summary, evidence, remediation, verification steps and output
hashes. Suricata EVE alerts can be ingested for the defensive view. Verified live: an Nmap scan of a lab container,
the report, and an approved verification re-test.

Not yet: ZAP, Burp Suite, OpenVAS, Ghidra, Volatility and Wazuh adapters; PentestGPT-style autonomous exploitation is
deliberately not included.

## Phase 5: research

Surface web fetching blocks private, loopback, link-local and metadata addresses (also after redirects), honours
robots.txt, refuses binaries, redacts credentials it finds, scans for prompt injection, flags malicious content,
classifies and guesses language (with optional translation by a model), and stores evidence with hashes. Web search
uses SearXNG or Brave if configured; arXiv works without a key. Private portals use a credential that is released
only after you approve that exact request.

The Tor zone (`POST /admin/research/tor/setup`) creates an internal Docker network with no internet route, plus a
Tor gateway container that is its only way out. Each onion fetch runs in a fresh locked-down container on that
network with no credentials, files or host environment; only `.onion` addresses and text content are accepted, and
results go to a separate dark-web evidence store. Dark-web identities cannot write memory, read files or
credentials, or use tools. Verified here: the internal network has no internet, and the fetcher speaks SOCKS5 with
remote DNS. Not verified here: a real Tor connection (this build environment cannot reach the Tor network).

## Phase 6: technology and model intelligence, self-improvement

The tech-intel agent reads GitHub, PyPI, npm, OSV, Hugging Face, arXiv and the official MCP registry, and keeps a
registry with available, evaluated, approved, rejected and deprecated states. Licence, maintenance, reliability and
known vulnerabilities are scored from data; hardware, performance, cost, compatibility, integration and
functionality stay blank until measured or entered. A new version of an approved item goes back to `available`.

Model benchmarking runs repeatable suites with automatic checks, records accuracy and latency, compares a candidate
with the deployed model and recommends only measured improvements. Deploying needs approval; rollback restores the
previous model. The health monitor checks policy integrity, the audit chain, databases, sandbox, engine link, disk
and stuck missions, gives advice from recurring failures, and only performs safe repairs. The improvement lab lets
agents propose prompt, routing or workflow changes; each is benchmarked, must not regress, needs approval, and is
rolled back automatically if the post-change health check fails. Backups cover every database, the policy, skills and
config; restore takes a safety backup first.

## Phase 7: cloud operation and dashboard

A persistent job queue with idempotency keys, leases and heartbeats: if your PC switches off mid-job, its lease
expires and a cloud worker takes over, and the PC can no longer record a duplicate result. Jobs can require
capabilities (for example `local-engine`) with a fallback when no such node is alive. The scheduler enqueues recurring
work (tech scan, health, backups) once per slot even with several schedulers. Deploy the server to a cloud VM with
`docker compose up -d`; on your PC run
`python -m fusion_os worker --server https://<your-server> --token <agent token> --capabilities local-engine`
so model calls use AI Fusion Engine Pro while the PC is on and fall back to the cloud model when it is off.

Mission control is at `/dashboard`: overview and missions, cybersecurity operations center, authorized testing,
vulnerability management, threat intelligence, deep research, technology discovery, knowledge graph, learning
history, skill lab, model benchmarking, approval center, security and permissions (including emergency stop),
recovery and rollback, and cloud/local resources. Every page reads from the live API; a test checks that every
endpoint the dashboard calls answers.

## Acceptance requirements: where each one stands

| # | Requirement | Status |
|---|---|---|
| 1 | Unfamiliar permitted missions | Mission runner works end to end (tested with a scripted model); needs a model configured on your side |
| 2 | Discover and develop new reusable skills | Verified: gap detected, skill drafted, validated in sandbox, approved, used |
| 3 | Authorized security testing and reports | Verified live with Nmap against a lab target |
| 4 | Isolated lawful Tor research | Isolation verified; a real Tor fetch not yet run |
| 5 | Continuous technology discovery | Implemented and scheduled; MCP registry verified live, other sources blocked by this build environment's network |
| 6 | Model and tool benchmarking | Verified with test models; real models need your engine or API key |
| 7 | Learning from failures | Verified |
| 8 | Verified installation of approved capabilities | Verified for skills and model deployment |
| 9 | Running with the PC off | Queue hand-over verified; the cloud deployment itself is not yet deployed |
| 10 | Secure recovery after failed updates | Verified: automatic rollback, backups and restore |
| 11 | Independent security policies | Verified: immutable rules, pinned policy, fail-closed |

## Run

```powershell
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"
.venv\Scripts\python -m pytest -q
.venv\Scripts\python -m fusion_os serve          # API on http://127.0.0.1:8790 (docs at /docs)
.venv\Scripts\python -m fusion_os admin-token    # your admin token
.venv\Scripts\python -m fusion_os add-agent researcher research
```

For the server, Docker Desktop is needed for the sandbox. The desktop app does not need Docker: skills and the Tor zone
fall back to process isolation (see [docs/desktop.md](docs/desktop.md)). Data lives in `%LOCALAPPDATA%\AIFusionOSPro`
(override with `FUSION_OS_HOME`).

## Desktop app (Windows)

Download `AI-Fusion-OS-Pro-Setup.exe` (or the MSI, or the portable zip) from the latest
[Windows desktop app](../../actions/workflows/windows-desktop.yml) run or release, check it against `SHA256SUMS.txt`,
and run it. No Docker, Python, Node.js or terminal commands are needed. Details, recovery and uninstall:
[docs/desktop.md](docs/desktop.md).

## API

Full list at `/docs` when the server runs. Agent token: `POST /v1/authorize`, `POST /v1/sandbox/exec`, `POST /v1/untrusted/scan`, `GET /v1/approvals/{id}`,
`POST /v1/memory`, `GET /v1/memory/search`, `GET /v1/memory/graph`, `POST /v1/episodes[/{id}/resolve]`, `GET /v1/lessons`,
`GET /v1/skills`, `GET /v1/skills/match`, `POST /v1/skills/submit`, `POST /v1/skills/{name}/{version}/register`, `POST /v1/skills/{name}/run`.
Admin token: `/admin/status`, `/admin/approvals[/{id}]`, `/admin/audit[/verify]`, `/admin/engagements`,
`/admin/agents`, `/admin/budgets/{mission}`, `/admin/memory[/{id}/release|retract|promote]`, `/admin/skills/{name}/rollback`, `/admin/policy`, `/admin/emergency-stop`, `/admin/resume`, `/admin/engine`.

## Known limits

- The controller runs in the same process as the API. Running it as its own OS service with its own account is
  the next hardening step.
- The admin token sits in a 0600 file; moving it to Windows Credential Manager is planned.
- Prompt-injection detection is pattern-based and will miss novel attacks. It is one layer: the real protection is
  that external content can never change policy, approvals or permissions.
- Skills can't use third-party packages yet. That needs a vetted, offline wheel cache, which comes with Phase 4.
- Fine-tuning models is not included yet: this build improves knowledge, workflows and prompts, and selects better
  models by benchmark.
- The Docker image and compose file have not been built or deployed from here.
