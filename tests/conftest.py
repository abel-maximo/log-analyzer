import pytest

from log_analyzer import audit
from log_analyzer.config import Settings
from log_analyzer.db import Repository
from log_analyzer.pipeline import Analyzer

EXAMPLE = """2026-09-29 14:32 LOGIN_FAILED user=admin ip=185.32.x.x
2026-09-29 14:32 LOGIN_FAILED user=admin ip=185.32.x.x
2026-09-29 14:33 LOGIN_FAILED user=admin ip=185.32.x.x
2026-09-29 14:34 LOGIN_SUCCESS user=admin ip=185.32.x.x"""


@pytest.fixture
def settings(tmp_path, monkeypatch):
    # isola do .env/ambiente do desenvolvedor
    for k in ("API_KEY", "LLM_PROVIDER", "LLM_API_KEY", "LLM_MODEL", "DATABASE_URL"):
        monkeypatch.delenv(k, raising=False)
    audit.reset_for_tests()
    s = Settings(_env_file=None, app_env="test", database_url=f"sqlite:///{tmp_path}/t.db",
                 audit_log_path=str(tmp_path / "audit.log"), pseudonym_key="test-key",
                 suspicious_ips="203.0.113.0/24")
    yield s
    audit.reset_for_tests()


@pytest.fixture
def repo(settings):
    return Repository(settings.database_url)


@pytest.fixture
def analyzer(settings, repo):
    return Analyzer(settings, repository=repo, use_default_llm=False)


@pytest.fixture
def example_lines():
    return EXAMPLE.splitlines()
