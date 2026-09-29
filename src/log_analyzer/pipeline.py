"""Orquestração: ingest -> parse -> anonimiza -> features -> regras -> scoring -> IA -> validação -> persiste.

Cada etapa é uma função pura/injetável; API e CLI apenas chamam `Analyzer.analyze`.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from . import features, rules, scoring
from .ai import AIAnalyzer, LLMClient, build_client, refine_or_fallback
from .audit import audit
from .config import Settings, get_settings
from .db import Repository
from .models import AnalysisReport, Finding, NormalizedEvent, Severity
from .parser import parse_lines
from .privacy import anonymize

MAX_EVIDENCE = 20


def _rule_finding(g: features.GroupFeatures, inds, cfg: rules.RuleConfig) -> Finding:
    ids = {i.id for i in inds}
    cls = rules.classify(ids, g)
    sev, sc, just = scoring.severity(inds)
    evs = g.events[:MAX_EVIDENCE]
    return Finding(
        severidade=sev, evento=cls.evento, indicadores=[i.descricao for i in inds],
        acao_recomendada=cls.acao, confianca=scoring.confidence(inds, len(g.events)),
        mitre_attack=cls.mitre, evidencias=[e.render() for e in evs], score=sc,
        indicadores_ids=[i.id for i in inds], justificativa=just, fonte="regras",
        grupo={"tipo": g.kind, **g.key, **{k: v for k, v in g.as_dict().items()
                                           if k not in ("kind", "key", "evidence_lines")}},
    )


class Analyzer:
    def __init__(self, settings: Settings | None = None, llm: LLMClient | None = None,
                 repository: Repository | None = None, use_default_llm: bool = True):
        self.s = settings or get_settings()
        client = llm if llm is not None else (build_client(self.s) if use_default_llm else None)
        self.ai = AIAnalyzer(client) if client else None
        self.repo = repository
        self.cfg = rules.RuleConfig(failure_threshold=self.s.failure_threshold,
                                    spray_user_threshold=self.s.spray_user_threshold)

    def detect(self, events: list[NormalizedEvent]) -> list[tuple[Finding, list[int]]]:
        """Retorna achados das regras + linhas de evidência (para a IA)."""
        groups = features.build_groups(events, self.s.window_minutes, self.s.failure_threshold)
        findings: list[tuple[Finding, set[int]]] = []
        for g in groups:
            inds = rules.evaluate(g, self.cfg)
            if rules.should_report(g, {i.id for i in inds}):
                findings.append((_rule_finding(g, inds, self.cfg), g.evidence_lines[:MAX_EVIDENCE]))
        # Deduplicação: achados de menor severidade já cobertos por um achado agregado
        # (spraying / distribuído) são ruído.
        covered: list[tuple[int, set[int]]] = [
            (f.severidade.rank, set(lines)) for f, lines in findings
            if rules.AGGREGATE_INDICATORS & set(f.indicadores_ids)]
        return [(f, lines) for f, lines in findings
                if rules.AGGREGATE_INDICATORS & set(f.indicadores_ids)
                or not any(f.severidade.rank < rank and set(lines) <= agg for rank, agg in covered)]

    def analyze(self, lines: list[str], *, source: str = "api", actor: str = "anonymous",
                use_llm: bool = True, persist: bool = True) -> AnalysisReport:
        raw, errors, total = parse_lines(lines, self.s.max_line_length)
        events = [anonymize(e, self.s) for e in raw]
        del raw  # dado bruto não sai deste escopo
        by_line = {e.line_no: e.render() for e in events}

        results: list[Finding] = []
        llm_used, ai_errors = False, []
        for f, lines in self.detect(events):
            if use_llm and self.ai and f.indicadores_ids:
                ev = {n: by_line[n] for n in lines}
                f, err = refine_or_fallback(self.ai, f, ev)
                llm_used |= f.fonte == "llm"
                if err:
                    ai_errors.append(err)
            results.append(f)

        results.sort(key=lambda f: (f.severidade.rank, f.score), reverse=True)
        overall = max((f.severidade for f in results), key=lambda s: s.rank, default=Severity.BAIXA)
        report = AnalysisReport(
            id=str(uuid.uuid4()), created_at=datetime.now(timezone.utc).replace(tzinfo=None),
            severidade_geral=overall, total_linhas=total, total_eventos=len(events),
            erros_parsing=errors, llm_utilizado=llm_used, analises=results,
        )
        if persist and self.repo:
            self.repo.save(report, events, source)
        audit(self.s.audit_log_path, "analyze", actor, analysis_id=report.id, source=source,
              lines=total, events=len(events), parse_errors=len(errors), findings=len(results),
              severity=overall.value, llm_used=llm_used, ai_errors=len(ai_errors), persisted=bool(persist and self.repo))
        return report
