"""Vercel entrypoint: serves the FastAPI app as a Python serverless function.

Vercel's filesystem is read-only except /tmp, and /tmp is wiped between cold starts, so state here is temporary.
Docker sandboxes, Tor, the background worker and the scheduler are not available on this host.
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("FUSION_OS_HOME", "/tmp/fusion_os")
os.environ.setdefault("FUSION_OS_WORKSPACE", "/tmp/fusion_os/workspace")
os.environ.setdefault("FUSION_OS_WORKER", "0")
os.environ.setdefault("FUSION_OS_SCHEDULER", "0")
Path(os.environ["FUSION_OS_WORKSPACE"]).mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fusion_os.api.server import create_app  # noqa: E402

app = create_app()

from fastapi.responses import RedirectResponse  # noqa: E402


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/dashboard")
