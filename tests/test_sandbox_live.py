"""Runs only where a Docker daemon is reachable (skipped otherwise)."""
import pytest

from fusion_os.sandbox.docker import DockerSandbox, SandboxSpec

sbx = DockerSandbox()
pytestmark = pytest.mark.skipif(not sbx.available()[0], reason="docker daemon not available")


def test_runs_isolated():
    r = sbx.run(SandboxSpec(image="alpine:3.20", command=["sh", "-c", "id -u; touch /x 2>&1 || echo RO; wget -q -T 3 -O- http://1.1.1.1 2>&1 || echo NONET"]))
    assert r.exit_code == 0, r.stderr
    assert r.stdout.splitlines()[0] == "65534"
    assert "RO" in r.stdout and "NONET" in r.stdout


def test_timeout_kills_container():
    r = sbx.run(SandboxSpec(image="alpine:3.20", command=["sleep", "30"], timeout_s=2))
    assert r.timed_out


def test_memory_limit():
    r = sbx.run(SandboxSpec(image="alpine:3.20", command=["sh", "-c", "cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes"], memory_mb=64))
    assert r.stdout.strip() == str(64 * 1024 * 1024)
