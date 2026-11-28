# Chat, skills, connectors and self-build

The desktop app now opens on a chat-first interface (`/app`). Mission Control (`/dashboard`) is one click away in
the sidebar and links back to the chat.

## Chat
- Chats are listed in the sidebar (star, rename, delete, search). They are stored in `<data>/chats.db`.
- Answers render Markdown: headings, lists, tables, code blocks with a copy button.
- Models are tried in the configured order (`FUSION_OS_LLM_ORDER`, default engine → queue → Anthropic). The
  provider that answered is shown under each answer.
- The emergency stop blocks chat as well (each turn is an `llm.chat` action).

## Links and files
- Paste a link in a message, or use **+ → Add a link**. Up to five links per message are read with the surface-web
  fetcher: public addresses only, text only, robots.txt respected, credentials redacted, prompt-injection scan.
  The model receives the text marked as untrusted data.
- **+ → Attach a text file** adds text files (up to 400 KB each), also marked untrusted.
- The assistant can also read pages itself with the `web_fetch` tool, and search with `web_search` when a search
  provider is configured (`BRAVE_API_KEY` or `FUSION_OS_SEARXNG_URL` in `desktop.env`).

## Coding
- Pick a project folder with the **Code** button in the composer (default: the workspace folder in the data folder).
  The app's own data folder (policy, tokens, audit log) and whole drives can't be projects.
- The assistant lists, searches and reads files there freely (`.git` is off limits), and changes them with
  `edit_file` (exact text replacement) or `write_file`. Each change is shown as a diff and waits for **Approve**
  (`files.write`).
- `run_code` runs Python in the sandbox without network, on a throwaway copy of the project, so a run can't change
  your files; use it for tests (`python -m unittest`). Each run waits for approval (`code.run`).
- In the Code menu you can let one chat apply edits or run code without asking (`files.write.preapproved`,
  `code.run.preapproved`). Choosing another folder turns both off again. Every write and run is in the audit log.

## OpenCode
The chat can hand larger coding tasks to [OpenCode](https://opencode.ai) (open source, MIT), when it is installed on
this PC (`npm install -g opencode-ai`, or set `FUSION_OS_OPENCODE` in `desktop.env` to the path of `opencode.exe`).
- Each hand-off (`opencode_task`) shows the task, the folder and the model, and waits for **Approve** (`code.delegate`).
- OpenCode works in the chat's project folder with a config this app writes: file edits allowed, commands, web
  fetches and folders outside the project denied. **Let OpenCode run commands** in the Code menu allows commands for
  that chat; they run on your PC outside the sandbox.
- When AI Fusion Engine Pro is running, OpenCode uses it as its model (local, no cost). Otherwise it uses the model
  set up in OpenCode itself, and the approval card says so.
- Afterwards the chat shows OpenCode's report, the tools it used and a diff of every changed file; the list of
  changed files goes to the audit log. Later hand-offs in the same chat continue the same OpenCode session.

## Skills
Two kinds:
- **Instruction skills** use Claude's format: a folder with `SKILL.md` (front matter `name` and `description`) and any
  reference files. Upload a `.zip` or `SKILL.md`, write one in the app, or **Import from Claude** (copies skills from
  `~/.claude/skills`; the originals are not changed). Enabled skills are listed to the model, which reads the full
  instructions when a request matches. Pick a skill for a whole chat with the **Skills** button in the composer.
  Scripts inside a skill folder are stored but never run from here. Skill text is scanned for prompt-injection
  patterns when added and warnings are shown.
- **Runnable skills** are the existing sandboxed Python skills (checks, tests, approval, sandbox at run time). The
  assistant can call any active one.

## Connectors (MCP)
- **Remote**: a Streamable HTTP MCP server URL (https only, or http on 127.0.0.1) with an optional bearer token.
- **Local program**: an MCP server started on this PC over stdio (for example `npx -y @modelcontextprotocol/server-filesystem C:\Docs`).
  It runs outside the sandbox with the access you give it, with a reduced environment: only basic Windows variables
  plus the ones you set. Only add programs you trust.
- **Import from Claude** reads the MCP servers set up for the Claude desktop app (`%APPDATA%\Claude\claude_desktop_config.json`,
  including the Microsoft Store copy) and Claude Code (`~/.claude.json`). Claude's files are not changed.
  Connectors added on claude.ai sign in through Claude's account and cannot be copied; add them with their URL
  and a token where the service offers one. OAuth sign-in for remote connectors is not supported yet.
- Each tool has a permission: **Ask** (default), **Allow** or **Off**. Ask means every call shows an approval card in
  the chat (Approve, Always allow, Deny). Tools whose names or annotations mean paying, sending, publishing,
  deleting or changing things can never be set to Allow; they always ask.
- Calls are security-controller actions (`connector.call` needs approval, `connector.call.preapproved` for tools you
  allowed) and are written to the audit log. Tool output is passed to the model as untrusted data.
- Connector settings, which can hold tokens, are kept in `<data>/connectors.json` (readable by this user only).

## Self-build
When no tool fits, the assistant can extend itself. Each extension shows what it built and waits for your approval:
- `build_skill`: writes a runnable Python skill (manifest, code, tests). It goes through the normal pipeline:
  static analysis, tests and an example run in the sandbox. If checks fail, the assistant gets the report and fixes
  it. Passing skills wait for your approval (`skill.register`) before they can run.
- `create_skill`: writes an instruction skill (SKILL.md). Added only after you approve.
- `add_connector`: proposes a remote https MCP connector. Added only after you approve (`connector.add`).

## Policy
The default policy gains `connector-preapproved` (allow) and `connector-ask` (require approval), and `connector.add`
joins the privileged actions that need approval. Version 4 adds `code-run` (require approval) and `chat-auto-approve`
(allow, used only when you switch on auto-approve for a chat). An unmodified earlier default policy is upgraded automatically; a
policy you edited is left alone, so add these rules yourself if you changed yours.

## Claude Code on your own model (offline)
Code menu > **Open Claude Code here (offline)** opens Claude Code in a new window with AI Fusion Engine Pro as its
model: `ANTHROPIC_BASE_URL` points at the engine's Anthropic-compatible `/v1/messages`, which now supports tool use,
so Claude Code's own tools, plugins, skills, hooks and local MCP servers keep working. Only that window is changed;
`~/.claude` is not touched, so Claude Code started any other way still uses your Anthropic account. The model is
loaded with a 32k-token context. Connectors added on claude.ai belong to your Anthropic account and need the internet.

## Self-improvement
- **Lessons.** Rate answers with 👍 or 👎. A 👎 with a note becomes a short rule (written by the model from your
  note) that is added to the prompt of later chats. Edit, pause or delete lessons in Improve > Lessons.
- **Interface.** Ask in a chat for a change to the app itself. The assistant reads its own page
  (`read_app_page`) and proposes exact edits (`change_app_page`). Each change is checked (the page must stay complete
  and balanced, and added lines may not touch approvals, policy, tokens, `eval` or outside web addresses), shown as
  a diff, and applied only after you approve (`app.ui.change`, never auto-approved). Versions are kept in
  `<data>/app_overlay`; Improve > Interface switches between them, and `/app?safe=1` always shows the installed page.
  Python code (server, security controller, policy) cannot be changed this way.
- **Model training (LoRA).** Improve > Model training trains a LoRA adapter for the engine's local model on your
  rated chats: answers from the local model you rated 👍 and better answers you wrote. Answers from cloud models are
  never used. Steps, each started by you: set up the trainer (~3 GB: PyTorch CUDA 12.1, transformers, peft,
  bitsandbytes, pinned versions; pip and the llama.cpp converter are SHA-256 checked), download the base model's
  original weights from Hugging Face (~15 GB for a 7B model), train (local models pause meanwhile; held-out loss is
  measured before and after), then deploy if you choose. The engine loads the model with `--lora-scaled`; Roll back
  restores the plain model. On a 6 GB GPU a 7B model trains with part of it in RAM, so expect hours per run.
