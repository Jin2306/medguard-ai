"""Runtime configuration read from the environment and an optional .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env", override=False)

DISCLAIMER = (
    "Decisions use MedGuard policies, static analysis, independently generated tests, "
    "and sandbox execution. Model output is advisory and is not proof. "
    "Passing these checks does not establish HIPAA compliance. "
    "Demonstration records are synthetic."
)


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _first(*names: str) -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


@dataclass(frozen=True)
class Settings:
    root: Path
    meta_api_key: str
    meta_model: str
    meta_base_url: str
    meta_auth_scheme: str
    mongodb_uri: str
    mongodb_db: str
    data_dir: Path
    sandbox_dir: Path
    sync_verification: bool

    @property
    def meta_configured(self) -> bool:
        return bool(self.meta_api_key and self.meta_model and self.meta_base_url)


def get_settings() -> Settings:
    data_dir = Path(os.environ.get("MEDGUARD_DATA_DIR", ROOT / "data")).expanduser()
    sandbox_dir = Path(os.environ.get("MEDGUARD_SANDBOX_DIR", ROOT / ".sandbox-runs")).expanduser()
    return Settings(
        root=ROOT,
        meta_api_key=os.environ.get("META_API_KEY", "").strip(),
        meta_model=os.environ.get("META_MODEL", "").strip(),
        meta_base_url=os.environ.get("META_BASE_URL", "").strip(),
        meta_auth_scheme=os.environ.get("META_AUTH_SCHEME", "Bearer").strip() or "Bearer",
        mongodb_uri=_first("MONGODB_URI", "MONGO_URI", "MONGODB_URL"),
        mongodb_db=os.environ.get("MONGODB_DB", "medguard").strip() or "medguard",
        data_dir=data_dir,
        sandbox_dir=sandbox_dir,
        sync_verification=_flag("MEDGUARD_SYNC"),
    )
