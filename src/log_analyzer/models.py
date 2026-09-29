"""Schemas de domínio (pydantic v2)."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    BAIXA = "BAIXA"
    MEDIA = "MÉDIA"
    ALTA = "ALTA"

    @property
    def rank(self) -> int:
        return {"BAIXA": 0, "MÉDIA": 1, "ALTA": 2}[self.value]

    @classmethod
    def from_rank(cls, r: int) -> "Severity":
        return [cls.BAIXA, cls.MEDIA, cls.ALTA][max(0, min(2, r))]


class RawEvent(BaseModel):
    """Evento recém-parseado. Contém dados brutos: NUNCA persistir nem enviar à IA."""
    line_no: int
    timestamp: datetime
    event_type: str
    user: str | None = None
    ip: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class NormalizedEvent(BaseModel):
    """Evento normalizado e anonimizado."""
    line_no: int
    timestamp: datetime
    event_type: str
    user: str | None            # pseudônimo (se MASK_USERS) ou original
    ip: str | None              # IP mascarado (ex.: 185.32.x.x)
    ip_ref: str | None          # hash estável p/ agrupamento sem expor o IP
    ip_scope: str               # external | internal | unknown
    ip_suspicious: bool = False
    privileged: bool = False
    off_hours: bool = False
    success: bool | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def render(self) -> str:
        """Linha de evidência já anonimizada (segura p/ relatório e LLM)."""
        return (f"L{self.line_no}: {self.timestamp:%Y-%m-%d %H:%M} {self.event_type} "
                f"user={self.user or '-'} ip={self.ip or '-'}")


class ParseError(BaseModel):
    line_no: int
    reason: str


class Indicator(BaseModel):
    id: str
    descricao: str
    peso: int


class Finding(BaseModel):
    """Uma análise (achado) — segue o formato de saída exigido."""
    severidade: Severity
    evento: str
    indicadores: list[str]
    acao_recomendada: str
    confianca: float = Field(ge=0, le=1)
    mitre_attack: list[str]
    evidencias: list[str] = Field(default_factory=list)
    # Explicabilidade
    score: int = 0
    indicadores_ids: list[str] = Field(default_factory=list)
    justificativa: str = ""
    fonte: str = "regras"  # regras | llm
    grupo: dict[str, Any] = Field(default_factory=dict)


class AnalysisReport(BaseModel):
    id: str
    created_at: datetime
    severidade_geral: Severity
    total_linhas: int
    total_eventos: int
    erros_parsing: list[ParseError] = Field(default_factory=list)
    llm_utilizado: bool = False
    analises: list[Finding] = Field(default_factory=list)
