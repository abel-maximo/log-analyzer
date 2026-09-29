"""Configuração centralizada via variáveis de ambiente / .env (12-factor)."""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Aplicação ---
    app_env: Literal["dev", "test", "prod"] = "dev"
    api_key: SecretStr | None = None  # vazio => auth desabilitada (apenas dev)
    max_lines_per_request: int = 50_000
    max_line_length: int = 4_096

    # --- Persistência ---
    database_url: str = "sqlite:///./data/analyzer.db"

    # --- Auditoria ---
    audit_log_path: str = "./data/audit.log"

    # --- Privacidade ---
    mask_ips: bool = True
    mask_users: bool = True
    # Chave HMAC para pseudonimização. OBRIGATÓRIO trocar em produção.
    pseudonym_key: SecretStr = SecretStr("change-me-in-production")

    # --- Detecção ---
    window_minutes: int = 10
    failure_threshold: int = 3
    spray_user_threshold: int = 5
    privileged_accounts: str = "admin,root,administrator,sa,sysadmin,superuser"
    business_hours_start: int = Field(default=7, ge=0, le=23)
    business_hours_end: int = Field(default=20, ge=1, le=24)
    suspicious_ips: str = ""  # CIDRs separados por vírgula

    # --- IA / LLM ---
    llm_provider: Literal["none", "anthropic", "openai"] = "none"
    llm_api_key: SecretStr | None = None
    llm_model: str | None = None
    llm_base_url: str | None = None  # p/ endpoints OpenAI-compatíveis (ex.: Ollama, vLLM)
    llm_timeout_seconds: float = 20.0

    @field_validator("privileged_accounts", "suspicious_ips")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()

    @field_validator("api_key", mode="before")
    @classmethod
    def _empty_api_key_is_unset(cls, v):
        if isinstance(v, str) and not v.strip():
            return None
        return v

    @property
    def privileged_set(self) -> frozenset[str]:
        return frozenset(a.strip().lower() for a in self.privileged_accounts.split(",") if a.strip())

    @property
    def suspicious_list(self) -> list[str]:
        return [c.strip() for c in self.suspicious_ips.split(",") if c.strip()]

    @property
    def llm_enabled(self) -> bool:
        return self.llm_provider != "none" and self.llm_api_key is not None and bool(self.llm_model)


@lru_cache
def get_settings() -> Settings:
    return Settings()
