"""Saída em texto, JSON e Markdown."""
from __future__ import annotations

import json

from .models import AnalysisReport, Finding
from .rules import MITRE_ALLOWED


def finding_to_dict(f: Finding) -> dict:
    """Formato público do contrato (igual ao exemplo) + campos de explicabilidade."""
    return {
        "severidade": f.severidade.value,
        "evento": f.evento,
        "indicadores": f.indicadores,
        "acao_recomendada": f.acao_recomendada,
        "confianca": f.confianca,
        "mitre_attack": f.mitre_attack,
        "evidencias": f.evidencias,
        "explicacao": {"score": f.score, "indicadores_ids": f.indicadores_ids,
                       "justificativa": f.justificativa, "fonte": f.fonte},
    }


def to_json(r: AnalysisReport, indent: int = 2) -> str:
    data = {
        "id": r.id,
        "created_at": r.created_at.isoformat(),
        "severidade_geral": r.severidade_geral.value,
        "total_linhas": r.total_linhas,
        "total_eventos": r.total_eventos,
        "llm_utilizado": r.llm_utilizado,
        "erros_parsing": [e.model_dump() for e in r.erros_parsing],
        "analises": [finding_to_dict(f) for f in r.analises],
    }
    return json.dumps(data, ensure_ascii=False, indent=indent)


def _finding_text(f: Finding) -> str:
    out = [f"Severidade: {f.severidade.value}", "", "Evento identificado:", f"{f.evento}.", "", "Indicadores:"]
    out += [f"- {i}" for i in f.indicadores] or ["- (nenhum)"]
    out += ["", "Ação recomendada:", f"{f.acao_recomendada}.", "",
            f"Confiança: {f.confianca:.2f} | MITRE ATT&CK: {', '.join(f.mitre_attack) or '-'} | Fonte: {f.fonte}",
            f"Justificativa: {f.justificativa}"]
    return "\n".join(out)


def to_text(r: AnalysisReport) -> str:
    if not r.analises:
        return (f"Severidade: {r.severidade_geral.value}\n\nNenhuma atividade suspeita identificada "
                f"({r.total_eventos} eventos analisados).")
    sep = "\n" + "-" * 60 + "\n"
    return sep.join(_finding_text(f) for f in r.analises)


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def to_markdown(r: AnalysisReport) -> str:
    lines = [
        "# Relatório — AI Security Log Analyzer", "",
        f"- **ID:** `{r.id}`",
        f"- **Gerado em:** {r.created_at:%Y-%m-%d %H:%M:%S} UTC",
        f"- **Severidade geral:** **{r.severidade_geral.value}**",
        f"- **Linhas / eventos válidos:** {r.total_linhas} / {r.total_eventos}",
        f"- **LLM utilizado:** {'sim' if r.llm_utilizado else 'não (regras)'}", "",
        "## Resumo", "", "| # | Severidade | Evento | Confiança | MITRE |", "|---|---|---|---|---|",
    ]
    for n, f in enumerate(r.analises, 1):
        lines.append(f"| {n} | {f.severidade.value} | {_md_escape(f.evento)} | {f.confianca:.2f} | {', '.join(f.mitre_attack) or '-'} |")
    if not r.analises:
        lines.append("| - | - | Nenhuma atividade suspeita | - | - |")
    for n, f in enumerate(r.analises, 1):
        lines += ["", f"## Achado {n} — {f.severidade.value}", "", f"**Evento:** {_md_escape(f.evento)}", "",
                  "**Indicadores:**", ""]
        lines += [f"- {i}" for i in f.indicadores] or ["- (nenhum)"]
        lines += ["", f"**Ação recomendada:** {_md_escape(f.acao_recomendada)}", "", "**MITRE ATT&CK:**", ""]
        lines += [f"- {t} — {MITRE_ALLOWED.get(t, '')}" for t in f.mitre_attack] or ["- n/a"]
        lines += ["", "**Explicabilidade:** " + _md_escape(f.justificativa), "", "**Evidências (anonimizadas):**",
                  "", "```"] + f.evidencias + ["```"]
    if r.erros_parsing:
        lines += ["", "## Linhas ignoradas", ""] + [f"- L{e.line_no}: {e.reason}" for e in r.erros_parsing[:50]]
    return "\n".join(lines) + "\n"


def render(r: AnalysisReport, fmt: str) -> str:
    return {"json": to_json, "md": to_markdown, "markdown": to_markdown, "text": to_text}[fmt](r)
