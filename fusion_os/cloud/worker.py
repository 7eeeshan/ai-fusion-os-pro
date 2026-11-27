"""Worker: leases jobs from the queue (in-process, or from a remote server over HTTPS) and runs registered handlers.

Run it in the cloud with `fusion-os worker --location cloud` next to the server, and on the PC with
`fusion-os worker --server https://your-server --token <agent token> --capabilities local-engine` so jobs that want
the local AI Fusion Engine Pro run there while the PC is on, and move to the cloud when it is off.
"""
from __future__ import annotations

import platform
import socket
import threading
import time
import traceback
from typing import Any, Callable, Optional

import httpx

Handler = Callable[[dict], Any]


class RemoteQueue:
    """Same lease/heartbeat/complete/fail interface, over the server's /v1/queue API."""

    def __init__(self, server: str, token: str, client: Optional[httpx.Client] = None):
        self.base = server.rstrip("/")
        self.c = client or httpx.Client(timeout=30, headers={"Authorization": f"Bearer {token}"})

    def lease(self, node_id: str, capabilities: list[str], location: str = "local") -> Optional[dict]:
        r = self.c.post(f"{self.base}/v1/queue/lease", json={"node_id": node_id, "capabilities": capabilities, "location": location})
        r.raise_for_status()
        return r.json().get("job")

    def heartbeat(self, job_id: str, node_id: str) -> bool:
        return self.c.post(f"{self.base}/v1/queue/{job_id}/heartbeat", json={"node_id": node_id}).json().get("ok", False)

    def complete(self, job_id: str, node_id: str, result: Any) -> bool:
        return self.c.post(f"{self.base}/v1/queue/{job_id}/complete", json={"node_id": node_id, "result": result}).json().get("ok", False)

    def fail(self, job_id: str, node_id: str, error: str, retry_in_s: float = 30) -> bool:
        return self.c.post(f"{self.base}/v1/queue/{job_id}/fail", json={"node_id": node_id, "error": error}).json().get("ok", False)


class Worker:
    def __init__(self, queue: Any, handlers: dict[str, Handler], capabilities: list[str], location: str = "local",
                 node_id: Optional[str] = None, poll_s: float = 2.0):
        self.q, self.handlers, self.caps, self.location = queue, handlers, capabilities, location
        self.node_id = node_id or f"{location}-{socket.gethostname()}-{platform.system().lower()}"[:64]
        self.poll_s = poll_s
        self._stop = threading.Event()

    def run_once(self) -> Optional[dict]:
        job = self.q.lease(self.node_id, self.caps, self.location)
        if not job:
            return None
        h = self.handlers.get(job["kind"])
        if h is None:
            self.q.fail(job["id"], self.node_id, f"no handler for {job['kind']} on {self.node_id}")
            return job
        beat = threading.Event()

        def heartbeat():
            while not beat.wait(max(1.0, (job["lease_until"] - time.time()) / 3)):
                if not self.q.heartbeat(job["id"], self.node_id):
                    return

        t = threading.Thread(target=heartbeat, daemon=True)
        t.start()
        try:
            res = h(job["payload"])
            beat.set()
            if not self.q.complete(job["id"], self.node_id, res):
                job["lost_lease"] = True  # someone else owns it now; our result is discarded
        except Exception as exc:
            beat.set()
            self.q.fail(job["id"], self.node_id, f"{exc}\n{traceback.format_exc()[-2000:]}")
        return job

    def run_forever(self) -> None:
        while not self._stop.is_set():
            try:
                if self.run_once() is None:
                    self._stop.wait(self.poll_s)
            except httpx.HTTPError:
                self._stop.wait(min(60, self.poll_s * 5))

    def stop(self) -> None:
        self._stop.set()
