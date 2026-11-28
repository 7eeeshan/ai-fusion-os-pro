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
joins the privileged actions that need approval. An unmodified earlier default policy is upgraded automatically; a
policy you edited is left alone, so add these rules yourself if you changed yours.
