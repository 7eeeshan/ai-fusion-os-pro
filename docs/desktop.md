# AI Fusion OS Pro for Windows

The desktop app runs everything on your PC with no Docker, WSL, Python, Node.js or terminal commands. It is built
by GitHub Actions ([workflow](../.github/workflows/windows-desktop.yml)) on every push; each run's artifact
`AI-Fusion-OS-Pro-windows-x64` holds:

| File | What it is |
|---|---|
| `AI-Fusion-OS-Pro-Setup.exe` | Installer wizard (per-user, no admin rights needed) |
| `AI-Fusion-OS-Pro-x64.msi` | MSI for managed or scripted installs |
| `AI-Fusion-OS-Pro-Portable-x64.zip` | Unzip and run; nothing installed |
| `DEPENDENCIES.txt` | Exact versions of the bundled Python, Tor, Python packages and Rust crates |
| `SHA256SUMS.txt` | SHA-256 of every file above |

Pushing a tag `v*` also creates a draft GitHub release with the same files.

## What is inside

- **Shell** (Tauri 2, `desktop/`): the window, the tray icon and a supervisor for the backend. Closing the window
  hides it; agents keep working. The tray has Open, Start at Windows sign-in, Restart backend, Open data folder and
  Quit (stops agents). Starting the app twice focuses the running one.
- **Backend** (`fusion_os`, unchanged API): the official python.org embeddable Python 3.12 with the hash-locked
  dependencies, started as `python -I -m fusion_os desktop`. It listens on 127.0.0.1 only, port 8790 or a free one.
- **Tor**: the Tor Expert Bundle, used only when you set up the dark-web research zone.

Downloads are verified at build time: Python with its Sigstore bundle (CPython release manager identity), Tor with
the signed checksum list (Tor Browser developers' key, pinned fingerprint), Python packages with pinned hashes.

## Sign-in

No admin token to paste. On each start the backend writes a random launch secret to
`%LOCALAPPDATA%\AIFusionOSPro\security\desktop.json`, which only your Windows account can read (the same protection
as the admin token itself). The shell opens the dashboard with it and the dashboard exchanges it for a session. In a
normal browser you can still sign in with the admin token (`python -m fusion_os admin-token` from a source checkout,
or the file `security\admin_token`).

## Running without Docker: what changes

Docker is used automatically when Docker Desktop is running. Without it:

| Feature | Without Docker |
|---|---|
| Missions, memory, approvals, audit, research, dashboard, queue and scheduler | Unchanged |
| Skills (validation, tests and runs) | Run in the **process sandbox** (below) |
| Dark-web research zone | Bundled `tor.exe` + fetcher in the process sandbox, allowed to reach only Tor's local SOCKS port |
| Raw agent commands (`/v1/sandbox/exec`) | Refused, unless you set `FUSION_OS_PROCESS_EXEC=1` |
| Security tools (nmap and other container images) | Need Docker; they say so instead of running |
| Networked skills | Need Docker |

**The process sandbox is weaker than Docker.** It runs only Python, with the app's interpreter in isolated mode, and
applies:
- an audit-hook guard, installed before the code loads and impossible to remove from Python, that blocks sockets,
  child processes, ctypes/native libraries, and file access outside the skill's throwaway work folder and the
  Python install; it binds everything it uses up front so the code cannot rebind its way around it, and hides its
  own frames;
- a Windows Job Object: memory cap, a single process, CPU-time limit, killed on timeout or when the app exits, no
  access to the desktop, clipboard or system settings;
- a scrubbed environment (no API keys, no user profile) and a private temp folder.

A container gives a kernel-level boundary; this does not. A flaw in CPython or in an allowed native module could
let code escape the guard. That is why only code that already passed static analysis (skills) uses it by default,
why skill registration still needs your approval, and why raw agent commands stay off. Install Docker Desktop if you
want container isolation; the app switches to it by itself.

## Settings

Edit `%LOCALAPPDATA%\AIFusionOSPro\desktop.env` (the tray's "Open data folder" opens it) and restart the backend from
the tray. Only `FUSION_OS_*` keys plus `ANTHROPIC_API_KEY`, `BRAVE_API_KEY`, `GITHUB_TOKEN`, `AFE_URL`, `AFE_TOKEN` and
`AFE_HOME` are read. If AI Fusion Engine Pro is installed, its API token is found automatically.

## Your existing data

The app uses `%LOCALAPPDATA%\AIFusionOSPro`. If that folder has no data yet but an earlier manual install kept its
data in the Claude app's redirected AppData (`%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Local\AIFusionOSPro`), the
first start **copies** it (admin token, policy, audit log, memory, skills, missions). The original is never changed,
and `migrated_from.txt` records where the copy came from. Install, upgrade and uninstall never delete your data.

The old helper scripts (`start-fusion.ps1`, `restart-os.ps1`, the "AI Fusion Autostart" scheduled task) are not
removed by the installer. Once the app works for you, run `uninstall-autostart.ps1` and turn on "Start at Windows
sign-in" in the tray instead, so the two do not both start a backend. (If they do, the second one sees the first
and exits.)

## Recovery

- **Backend crashed**: the shell restarts it with back-off. After 5 crashes in 5 minutes it waits a minute and shows
  the reason; the log is `logs\backend.log` in the data folder.
- **Interrupted missions**: a crash, reboot or Quit marks running missions as interrupted; resume them from the
  dashboard. Missions waiting for an approval continue when it arrives.
- **Repair or upgrade**: run the newer (or the same) `Setup.exe` over the installed app. The installer stops the
  backend first.
- **Uninstall**: Windows Settings > Apps > AI Fusion OS Pro. Your data folder stays; delete it yourself if you want a
  clean slate.
- **Bad update or broken policy**: the existing backups and rollback in the dashboard (System recovery and rollback).

## Building it yourself

On Windows with Python 3.12, Node.js 22, Rust and Git Bash:

```powershell
./packaging/windows/build-backend.ps1
bash ./packaging/windows/build-tor.sh
cd desktop; npm ci; npx tauri build; cd ..
./packaging/windows/collect.ps1
```

For development against a source checkout, set `FUSION_OS_DEV_PYTHON` to your venv's `python.exe` and run
`npx tauri dev` in `desktop/`.

## Not in this milestone yet

These parts of the desktop specification are planned for the next milestones: the AI runtime manager (Ollama,
llama.cpp, AirLLM, CUDA/Vulkan detection, model downloads and routing), a Windows service that runs before sign-in,
Credential Manager/DPAPI for stored keys, the expanded Mission Control (workflow designer, MCP manager, hardware
monitor, update center, light theme), code signing and signed auto-updates, and bundling AI Fusion Engine Pro.
Until code signing is set up, Windows SmartScreen will warn that the installer is from an unknown publisher; check
the SHA-256 against `SHA256SUMS.txt` from the same build.
