"""Runs INSIDE the isolated fetcher container (standard library only). Reads {"url": ...} on stdin, fetches it through
the Tor SOCKS5 proxy with remote DNS, and prints JSON. It never executes or saves what it downloads."""
import json
import os
import socket
import ssl
import struct
import sys
from urllib.parse import urlsplit

PROXY = (os.environ.get("TOR_HOST", "fos-tor"), int(os.environ.get("TOR_PORT", "9050")))
MAX = int(os.environ.get("MAX_BYTES", "2000000"))
OK_TYPES = ("text/html", "text/plain")


def socks_connect(host, port):
    s = socket.create_connection(PROXY, timeout=60)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise OSError("proxy refused")
    h = host.encode("idna")
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port))
    rep = s.recv(10)
    if len(rep) < 2 or rep[1] != 0:
        raise OSError(f"tor connect failed (code {rep[1] if len(rep) > 1 else '?'})")
    return s


def fetch(url):
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not (p.hostname or "").endswith(".onion"):
        return {"error": "only .onion http(s) URLs are allowed"}
    port = p.port or (443 if p.scheme == "https" else 80)
    s = socks_connect(p.hostname, port)
    if p.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # onion addresses authenticate the service themselves
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=p.hostname)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: {p.hostname}\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html,text/plain\r\n"
              f"Connection: close\r\n\r\n".encode())
    data = b""
    while len(data) <= MAX:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1]) if lines and len(lines[0].split()) > 1 else 0
    headers = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
    ctype = headers.get("content-type", "").split(";")[0].lower()
    if ctype and not ctype.startswith(OK_TYPES):
        return {"status": status, "error": f"content type {ctype} refused"}
    if "chunked" in headers.get("transfer-encoding", ""):
        out, rest = b"", body
        while rest:
            size_s, _, rest = rest.partition(b"\r\n")
            try:
                size = int(size_s.split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                break
            out, rest = out + rest[:size], rest[size + 2:]
        body = out
    return {"status": status, "content_type": ctype, "location": headers.get("location"),
            "body": body[:MAX].decode("utf-8", "replace"), "truncated": len(data) > MAX}


if __name__ == "__main__":
    try:
        print(json.dumps(fetch(json.loads(sys.stdin.read())["url"])))
    except Exception as exc:
        print(json.dumps({"error": str(exc)[:500]}))
