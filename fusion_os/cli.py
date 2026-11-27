"""Command line: `fusion-os serve | desktop | status | admin-token | add-agent | approvals | approve | deny | stop | resume | verify-audit`."""
from __future__ import annotations

import argparse
import json
import sys

from .security.controller import SecurityController


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="fusion-os")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8790)
    dk = sub.add_parser("desktop", help="run the backend for the desktop app (loopback only, single instance)")
    dk.add_argument("--port", type=int, default=8790)
    dk.add_argument("--open", action="store_true", help="open the dashboard in the default browser")
    sub.add_parser("desktop-stop", help="stop a running desktop backend")
    sub.add_parser("status")
    sub.add_parser("admin-token")
    a = sub.add_parser("add-agent")
    a.add_argument("agent_id")
    a.add_argument("zones", nargs="+")
    sub.add_parser("approvals")
    for name in ("approve", "deny"):
        x = sub.add_parser(name)
        x.add_argument("approval_id")
        x.add_argument("--note", default="")
    st = sub.add_parser("stop")
    st.add_argument("reason", nargs="?", default="manual")
    sub.add_parser("resume")
    sub.add_parser("verify-audit")
    w = sub.add_parser("worker", help="run a remote worker that serves jobs for a server (e.g. local model calls)")
    w.add_argument("--server", required=True)
    w.add_argument("--token", required=True, help="agent token issued by the server admin")
    w.add_argument("--capabilities", default="local-engine")
    w.add_argument("--location", default="local")
    args = p.parse_args(argv)

    if args.cmd == "serve":
        import uvicorn
        from .api.server import create_app
        if args.host not in ("127.0.0.1", "localhost", "::1"):
            print("warning: binding to a non-loopback address exposes the API to your network", file=sys.stderr)
        uvicorn.run(create_app(), host=args.host, port=args.port)
        return 0
    if args.cmd == "desktop":
        from . import desktop
        return desktop.run(args.port, args.open)
    if args.cmd == "desktop-stop":
        from . import desktop
        return 0 if desktop.stop_running() else 1
    if args.cmd == "worker":
        from .cloud.worker import RemoteQueue, Worker
        from .llm import EngineLLM
        llm = EngineLLM()
        handlers = {"llm.complete": lambda p: llm.complete(p["system"], p["prompt"], int(p.get("max_tokens", 2000)))}
        wk = Worker(RemoteQueue(args.server, args.token), handlers, args.capabilities.split(","), args.location)
        print(f"worker {wk.node_id} serving {sorted(handlers)} for {args.server}")
        wk.run_forever()
        return 0
    ctl = SecurityController()
    if args.cmd == "status":
        print(json.dumps(ctl.status(), indent=2))
    elif args.cmd == "admin-token":
        print(ctl.admin_token())
    elif args.cmd == "add-agent":
        print(ctl.register_agent(args.agent_id, args.zones))
    elif args.cmd == "approvals":
        print(json.dumps(ctl.approvals.list("pending"), indent=2, default=str))
    elif args.cmd in ("approve", "deny"):
        ok = ctl.decide_approval(args.approval_id, args.cmd == "approve", "admin-cli", args.note)
        print("ok" if ok else "not pending")
        return 0 if ok else 1
    elif args.cmd == "stop":
        ctl.emergency_stop("admin-cli", args.reason)
        print("emergency stop active")
    elif args.cmd == "resume":
        ctl.resume("admin-cli")
        print("resumed")
    elif args.cmd == "verify-audit":
        r = ctl.audit.verify()
        print(json.dumps(r, indent=2))
        return 0 if r["ok"] else 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
