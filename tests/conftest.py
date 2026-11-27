import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("FUSION_OS_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("AFE_URL", "http://127.0.0.1:1")
