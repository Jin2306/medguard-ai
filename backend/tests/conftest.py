import pytest
from fastapi.testclient import TestClient

_SECRET_ENV = ("MONGODB_URI", "MONGO_URI", "MONGODB_URL", "META_API_KEY", "META_MODEL", "META_BASE_URL")


def _clear_secrets(monkeypatch) -> None:
    for name in _SECRET_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MEDGUARD_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MEDGUARD_SANDBOX_DIR", str(tmp_path / "sandbox"))
    monkeypatch.setenv("MEDGUARD_SYNC", "1")
    _clear_secrets(monkeypatch)
    from app.main import app
    from app.store import reset_store

    _clear_secrets(monkeypatch)
    reset_store()
    with TestClient(app) as test_client:
        yield test_client
    reset_store()
