"""Bootstrap that runs as the main program of every process-sandbox child (see process.py).

It installs a CPython audit hook before any untrusted code is loaded. Audit hooks cannot be removed from Python
code, and the hook blocks the usual ways out:
- network: any socket use, except one connection to an explicitly allowed host:port (the local Tor SOCKS port);
- processes: subprocess, os.system/exec/spawn/fork/startfile, and the native modules behind them;
- native code: ctypes/cffi and loading extension DLLs that are not part of the Python install;
- files: writes, deletes, renames and directory listings outside the work folder, and reads outside the work folder
  and the Python installation.

This is a guardrail around Python code, not a kernel boundary: a flaw in CPython or an allowed native module could
still escape it. That is why it only runs code that already passed static analysis, why networked runs are refused
and why the parent also applies OS limits (Windows Job Object / POSIX rlimits) and a timeout. Use Docker for
untrusted code that needs stronger isolation.

Usage: python -I -B guard.py <config.json>
config: work, tmp, mode "script"|"module"|"code", target, args, allow_connect
Standard library only.
"""
import json
import os
import sys

_BLOCKED_MODULES = frozenset({
    "ctypes", "_ctypes", "cffi", "_cffi_backend", "subprocess", "_posixsubprocess", "_winapi", "_overlapped",
    "multiprocessing", "_multiprocessing", "socket", "_socket", "ssl", "_ssl", "select", "selectors", "asyncio",
    "winreg", "_winreg", "msvcrt", "mmap", "pty", "fcntl", "resource",
    "webbrowser", "urllib.request", "http.client", "ftplib", "smtplib", "imaplib", "poplib", "telnetlib",
    "xmlrpc.client", "_xxsubinterpreters", "_interpreters", "_testcapi", "_testinternalcapi", "gc",
})
_NET_MODULES = frozenset({"socket", "_socket", "ssl", "_ssl", "select", "selectors"})
_BLOCKED_EVENTS = frozenset({
    "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty",
    "os.startfile", "os.kill", "os.killpg", "pty.spawn", "_winapi.CreateProcess", "_winapi.OpenProcess",
    "_winapi.TerminateProcess", "ctypes.dlopen", "ctypes.dlsym", "ctypes.cdata", "ctypes.call_function",
    "ctypes.addressof", "ctypes.string_at", "ctypes.wstring_at", "winreg.OpenKey", "winreg.CreateKey",
    "winreg.ConnectRegistry", "sys.addaudithook", "sys.setprofile", "sys.settrace", "sys.remote_exec",
    "socket.sethostname", "webbrowser.open", "urllib.Request",
    "shutil.chown", "os.chown", "os.chflags", "os.lchflags", "os.setxattr", "os.removexattr",
    "cpython.PyInterpreterState_New", "cpython.run_command", "cpython.run_file", "cpython.run_interactivehook",
    "cpython.run_module", "cpython.run_startup", "gc.get_objects", "gc.get_referrers", "gc.get_referents",
    "_thread.start_new_thread",
})
_WRITE_PATH_EVENTS = frozenset({"os.remove", "os.rename", "os.rmdir", "os.mkdir", "os.chmod", "os.symlink", "os.link",
                      "os.truncate", "os.utime", "shutil.rmtree", "shutil.copyfile", "shutil.copymode",
                      "shutil.copystat", "shutil.copytree", "shutil.move", "shutil.make_archive",
                      "shutil.unpack_archive", "tempfile.mkdtemp", "tempfile.mkstemp", "os.chdir"})
_LIST_EVENTS = frozenset({"os.listdir", "os.scandir", "glob.glob", "glob.glob/2", "os.walk", "pathlib.Path.glob",
                "pathlib.Path.rglob"})


class SandboxViolation(PermissionError):
    pass


def install(cfg):
    """Install the audit hook.

    The hook never calls Python-level library code (os.path, posixpath, builtins looked up by name) and never runs
    methods of objects the untrusted code made: everything it uses is a C function bound here, and arguments are
    checked by exact type first. Untrusted code therefore cannot weaken it by rebinding module attributes or builtins
    or by passing objects with custom __eq__/__fspath__. Its own frames are hidden from traceback inspection, so their
    closures cannot be edited either."""
    _getcwd, _lstat, _readlink, _fsdecode = os.getcwd, os.lstat, os.readlink, os.fsdecode
    _str, _bytes, _int, _tuple, _type, _len, _range = str, bytes, int, tuple, type, len, range
    _wflags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    _V = SandboxViolation
    win = os.name == "nt"
    sep = "\\" if win else "/"
    _final = None
    if win:
        import nt
        _final = nt._getfinalpathname

    def split_abs(p):
        """Absolute, '..'-free path components (no symlink resolution). Windows: (drive, parts)."""
        if win:
            p = p.replace("/", "\\")
            if p.startswith("\\\\"):
                raise _V("sandbox: UNC and device paths are not allowed")
            cwd = _getcwd()
            if _len(p) >= 2 and p[1] == ":":
                drive, rest = p[:2].upper(), p[2:]
                if not rest.startswith("\\"):
                    if drive != cwd[:2].upper():
                        raise _V("sandbox: drive-relative paths are not allowed")
                    rest = cwd[2:] + "\\" + rest
            elif p.startswith("\\"):
                drive, rest = cwd[:2].upper(), p
            else:
                drive, rest = cwd[:2].upper(), cwd[2:] + "\\" + p
        else:
            drive, rest = "", p if p.startswith("/") else _getcwd() + "/" + p
        parts = []
        for c in rest.split(sep):
            if c == "" or c == ".":
                continue
            if c == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(c)
        return drive, parts

    def resolve(p):
        drive, parts = split_abs(p)
        if win:
            # Resolve links/junctions/short names on the longest existing prefix with the C API, keep the rest.
            for i in _range(_len(parts), -1, -1):
                head = drive + "\\" + "\\".join(parts[:i])
                try:
                    real = _final(head)
                except OSError:
                    continue
                if real.startswith("\\\\?\\UNC\\"):
                    raise _V("sandbox: network paths are not allowed")
                if real.startswith("\\\\?\\"):
                    real = real[4:]
                tail = parts[i:]
                out = real.rstrip("\\") + ("\\" + "\\".join(tail) if tail else "")
                return out.lower()
            return (drive + "\\" + "\\".join(parts)).lower()
        resolved = []
        todo = parts
        hops = 0
        while todo:
            c, todo = todo[0], todo[1:]
            cand = "/" + "/".join(resolved + [c])
            try:
                st = _lstat(cand)
                is_link = (st.st_mode & 0o170000) == 0o120000
            except OSError:
                is_link = False
            if not is_link:
                resolved.append(c)
                continue
            hops += 1
            if hops > 40:
                raise _V("sandbox: too many symlinks")
            target = _readlink(cand)
            _, tparts = split_abs(target if target.startswith("/") else "/" + "/".join(resolved) + "/" + target)
            resolved, todo = [], tparts + todo
        return "/" + "/".join(resolved)

    def norm(p):
        t = _type(p)
        if t is _int:
            return None  # an fd: it was opened under the same checks
        if t is _bytes:
            p = _fsdecode(p)
        elif t is not _str:
            # Custom path objects could return one path to the check and another to the open call.
            raise _V("sandbox: pass file paths as plain strings")
        if "\x00" in p:
            raise _V("sandbox: bad path")
        return resolve(p)

    def under(path, roots):
        for r in roots:
            if path == r or path.startswith(r.rstrip(sep) + sep):
                return True
        return False

    here = norm(os.path.dirname(os.path.abspath(__file__)))
    work, tmp = norm(_str(cfg["work"])), norm(_str(cfg["tmp"]))
    write_roots = (work, tmp)
    install_roots = _tuple(sorted({norm(os.path.abspath(p)) for p in (
        sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix, os.path.dirname(sys.executable)) if p}))
    read_roots = write_roots + install_roots + (here,)
    allow = cfg.get("allow_connect")
    allow_addr = (_str(allow[0]), _int(allow[1])) if allow else None
    blocked = frozenset(_BLOCKED_MODULES - _NET_MODULES if allow_addr else _BLOCKED_MODULES)
    blocked_top = frozenset({"ctypes", "cffi", "multiprocessing", "asyncio"})
    # Drop already-imported dangerous modules so untrusted code has to import them again (and gets refused).
    for name in list(sys.modules):
        if name in blocked or name.split(".")[0] in blocked_top:
            sys.modules.pop(name, None)
    busy = [False]
    own_codes = []

    def hook(event, args, _be=_BLOCKED_EVENTS, _wpe=_WRITE_PATH_EVENTS, _le=_LIST_EVENTS):
        if event == "object.__getattr__":
            # Hide the guard's own frames (reachable from a traceback) so their closures cannot be edited.
            if busy[0] or _len(args) < 2 or args[1] != "tb_frame":
                return
            busy[0] = True
            try:
                code = args[0].tb_frame.f_code
            finally:
                busy[0] = False
            for c in own_codes:
                if code is c:
                    raise _V("sandbox: inspecting the guard is not allowed")
            return
        if event in _be:
            raise _V("sandbox: " + event + " is not allowed")
        if event == "import":
            name = args[0]
            if _type(name) is not _str:
                raise _V("sandbox: bad module name")
            if name in blocked or name.split(".")[0] in blocked_top:
                raise _V("sandbox: import " + name + " is not allowed")
        elif event == "open":
            path, mode = args[0], args[1]
            p = norm(path)
            if p is None:
                return
            writing = False
            if mode is not None:
                if _type(mode) is not _str:
                    raise _V("sandbox: bad open mode")
                writing = "w" in mode or "a" in mode or "x" in mode or "+" in mode
            flags = args[2] if _len(args) > 2 and _type(args[2]) is _int else 0
            if flags & _wflags:
                writing = True
            if writing and not under(p, write_roots):
                raise _V("sandbox: writing " + p + " is not allowed")
            if not writing and not under(p, read_roots):
                raise _V("sandbox: reading " + p + " is not allowed")
        elif event in _wpe:
            for a in args[:2]:
                if a is None or _type(a) is _int:
                    continue
                p = norm(a)
                if not under(p, write_roots):
                    raise _V("sandbox: " + event + " on " + p + " is not allowed")
        elif event in _le:
            a = args[0] if args else "."
            if a is not None and _type(a) is not _int:
                p = norm(a)
                if not under(p, read_roots):
                    raise _V("sandbox: listing " + p + " is not allowed")
        elif event == "import.dlopen" or event == "_ctypes.dlopen":
            p = norm(args[0]) if args and args[0] else None
            if p is None or not under(p, install_roots):
                raise _V("sandbox: loading a native library is not allowed")
        elif event.startswith("socket."):
            if allow_addr is None:
                raise _V("sandbox: network access is not allowed")
            if event == "socket.getaddrinfo":
                host, port = args[0], args[1]
                if _type(host) is _bytes:
                    host = _fsdecode(host)
                if _type(host) is not _str or _type(port) is not _int or host != allow_addr[0] or port != allow_addr[1]:
                    raise _V("sandbox: name resolution is not allowed")
            elif event == "socket.connect":
                addr = args[1]
                if not (_type(addr) is _tuple and _len(addr) >= 2 and _type(addr[0]) is _str
                        and _type(addr[1]) is _int and addr[0] == allow_addr[0] and addr[1] == allow_addr[1]):
                    raise _V("sandbox: this connection is not allowed")
            elif event in ("socket.bind", "socket.sendto", "socket.sendmsg"):
                raise _V("sandbox: " + event + " is not allowed")
            elif event == "socket.__new__":
                family = args[1] if _len(args) > 1 else None
                if not (family is None or (_type(family) is _int and family in (2, 10, 23, -1))):
                    raise _V("sandbox: this socket family is not allowed")

    own_codes.extend([hook.__code__, norm.__code__, under.__code__, resolve.__code__, split_abs.__code__])
    sys.addaudithook(hook)


def main(argv):
    if len(argv) != 2:
        print("usage: guard.py <config.json>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        cfg = json.load(f)
    os.chdir(cfg["work"])
    sys.path[:] = [cfg["work"]] + [p for p in sys.path if p and os.path.isdir(p) and not p.startswith(cfg["work"])]
    import runpy  # noqa: needed before the hook so the runner itself is loaded from the install
    import unittest  # noqa: preload: the hook lists directories, and test discovery needs this from the install
    # Preload stdlib modules that import blocked native helpers internally (shutil and argparse use _winapi on
    # Windows). Their dangerous calls still raise audit events the hook refuses, and the Windows job allows no child
    # process, but fresh imports of those helpers by untrusted code stay blocked.
    import argparse  # noqa
    import shutil  # noqa
    install(cfg)
    if cfg["mode"] == "code":
        sys.argv = ["-c"] + list(cfg.get("args", []))
        import __main__
        exec(compile(cfg["target"], "<string>", "exec"), vars(__main__))
        return 0
    sys.argv = [cfg["target"]] + list(cfg.get("args", []))
    if cfg["mode"] == "module":
        runpy.run_module(cfg["target"], run_name="__main__", alter_sys=True)
    else:
        runpy.run_path(cfg["target"], run_name="__main__")
    return 0


if __name__ == "__main__":
    try:
        code = main(sys.argv)
    except SystemExit:
        raise
    except SandboxViolation as exc:
        print(str(exc), file=sys.stderr)
        code = 126
    sys.exit(code)
