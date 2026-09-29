"""Persistência (SQLAlchemy 2.x). SQLite por padrão; PostgreSQL via DATABASE_URL.

Minimização (LGPD): persistimos apenas eventos NORMALIZADOS e mascarados..
"""
from __future__ import annotations

import os
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .models import AnalysisReport, Finding, NormalizedEvent, ParseError, Severity


class Base(DeclarativeBase):
    pass


class AnalysisRow(Base):
    __tablename__ = "analyses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    source: Mapped[str] = mapped_column(String(32))
    severidade_geral: Mapped[str] = mapped_column(String(8), index=True)
    total_linhas: Mapped[int] = mapped_column(Integer)
    total_eventos: Mapped[int] = mapped_column(Integer)
    llm_utilizado: Mapped[bool] = mapped_column(Boolean, default=False)
    erros_parsing: Mapped[list] = mapped_column(JSON, default=list)
    findings: Mapped[list["FindingRow"]] = relationship(cascade="all, delete-orphan", lazy="selectin")
    events: Mapped[list["EventRow"]] = relationship(cascade="all, delete-orphan", lazy="raise")  # nunca carregado implicitamente


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    severidade: Mapped[str] = mapped_column(String(8), index=True)
    evento: Mapped[str] = mapped_column(Text)
    acao_recomendada: Mapped[str] = mapped_column(Text)
    confianca: Mapped[float] = mapped_column(Float)
    score: Mapped[int] = mapped_column(Integer)
    fonte: Mapped[str] = mapped_column(String(16))
    payload: Mapped[dict] = mapped_column(JSON)  # Finding completo (indicadores, mitre, evidências)


class EventRow(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    line_no: Mapped[int] = mapped_column(Integer)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    user_ref: Mapped[str | None] = mapped_column(String(128))
    ip_masked: Mapped[str | None] = mapped_column(String(64))
    ip_scope: Mapped[str] = mapped_column(String(16))
    success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)


class Repository:
    def __init__(self, url: str):
        if url.startswith("sqlite:///"):
            path = url.removeprefix("sqlite:///")
            if path and path != ":memory:":
                os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.engine = create_engine(url, future=True, pool_pre_ping=True)
        Base.metadata.create_all(self.engine)  # MVP; produção => Alembic
        self._session = sessionmaker(self.engine, expire_on_commit=False)

    def save(self, report: AnalysisReport, events: list[NormalizedEvent], source: str) -> None:
        with self._session.begin() as s:
            row = AnalysisRow(
                id=report.id, created_at=report.created_at, source=source,
                severidade_geral=report.severidade_geral.value, total_linhas=report.total_linhas,
                total_eventos=report.total_eventos, llm_utilizado=report.llm_utilizado,
                erros_parsing=[e.model_dump() for e in report.erros_parsing],
            )
            row.findings = [FindingRow(severidade=f.severidade.value, evento=f.evento,
                                       acao_recomendada=f.acao_recomendada, confianca=f.confianca,
                                       score=f.score, fonte=f.fonte, payload=f.model_dump(mode="json"))
                            for f in report.analises]
            row.events = [EventRow(line_no=e.line_no, ts=e.timestamp, event_type=e.event_type, user_ref=e.user,
                                   ip_masked=e.ip, ip_scope=e.ip_scope, success=e.success) for e in events]
            s.add(row)

    @staticmethod
    def _to_report(r: AnalysisRow) -> AnalysisReport:
        return AnalysisReport(
            id=r.id, created_at=r.created_at, severidade_geral=Severity(r.severidade_geral),
            total_linhas=r.total_linhas, total_eventos=r.total_eventos, llm_utilizado=r.llm_utilizado,
            erros_parsing=[ParseError(**e) for e in (r.erros_parsing or [])],
            analises=[Finding.model_validate(f.payload) for f in r.findings],
        )

    def get(self, analysis_id: str) -> AnalysisReport | None:
        with self._session() as s:
            r = s.get(AnalysisRow, analysis_id)
            return self._to_report(r) if r else None

    def list(self, limit: int = 50, severity: str | None = None) -> list[AnalysisReport]:
        with self._session() as s:
            q = select(AnalysisRow).order_by(AnalysisRow.created_at.desc()).limit(min(limit, 500))
            if severity:
                q = q.where(AnalysisRow.severidade_geral == severity)
            return [self._to_report(r) for r in s.scalars(q)]
