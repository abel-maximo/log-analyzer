"""Refinamento de achados via LLM com validação estrita (guardrails) e fallback.

Política de segurança:
- A IA NUNCA cria indicadores, técnicas MITRE ou evidências fora do que as regras/logs fornecem.
- A IA pode ESCALAR a severidade em no máximo 1 nível, mas NUNCA rebaixar:
  um log manipulado (prompt injection) não consegue "esconder" um ataque.
- Qualquer violação => descarta a resposta e mantém o achado das regras (fallback).
"""
from __future__ import annotations

import json
import logging
import re

from pydantic import BaseModel, Field, ValidationError

from ..models import Finding, Severity
from ..rules import CATALOG, MITRE_ALLOWED
from .prompt import SYSTEM_PROMPT, build_user_prompt
from .providers import LLMClient, LLMError

log = logging.getLogger(__name__)
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class AIValidationError(ValueError):
    pass


class LLMOutput(BaseModel):
    severidade: Severity
    evento: str = Field(min_length=5, max_length=300)
    indicadores_ids: list[str]
    acao_recomendada: str = Field(min_length=5, max_length=500)
    confianca: float = Field(ge=0, le=1)
    mitre_attack: list[str]
    evidencias_linhas: list[int]
    justificativa: str = Field(default="", max_length=1000)


def _extract_json(text: str) -> dict:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        raise AIValidationError("resposta sem objeto JSON")
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise AIValidationError(f"JSON inválido: {exc.msg}") from exc


def validate(out: LLMOutput, rule: Finding, valid_lines: set[int]) -> None:
    extra = set(out.indicadores_ids) - set(rule.indicadores_ids)
    if extra:
        raise AIValidationError(f"indicadores não detectados pelas regras: {sorted(extra)}")
    if not out.indicadores_ids and rule.indicadores_ids:
        raise AIValidationError("IA descartou todos os indicadores")
    bad_mitre = set(out.mitre_attack) - set(MITRE_ALLOWED)
    if bad_mitre:
        raise AIValidationError(f"técnicas MITRE fora da allowlist: {sorted(bad_mitre)}")
    bad_lines = set(out.evidencias_linhas) - valid_lines
    if bad_lines:
        raise AIValidationError(f"evidências inexistentes: {sorted(bad_lines)}")
    delta = out.severidade.rank - rule.severidade.rank
    if delta < 0:
        raise AIValidationError("IA tentou rebaixar a severidade (não permitido)")
    if delta > 1:
        raise AIValidationError("IA escalou severidade em mais de 1 nível")


class AIAnalyzer:
    def __init__(self, client: LLMClient):
        self.client = client

    def refine(self, rule: Finding, evidence: dict[int, str]) -> Finding:
        """Retorna Finding refinado pela IA. Levanta LLMError/AIValidationError em falha."""
        prompt = build_user_prompt(rule, list(evidence.values()), list(evidence))
        raw = self.client.complete(SYSTEM_PROMPT, prompt)
        try:
            out = LLMOutput.model_validate(_extract_json(raw))
        except ValidationError as exc:
            raise AIValidationError(f"schema inválido: {exc.error_count()} erro(s)") from exc
        validate(out, rule, set(evidence))

        ids = [i for i in rule.indicadores_ids if i in set(out.indicadores_ids)]  # mantém ordem das regras
        lines = out.evidencias_linhas or list(evidence)
        return rule.model_copy(update={
            "severidade": out.severidade,
            "evento": _CTRL.sub(" ", out.evento).strip(),
            "indicadores_ids": ids,
            "indicadores": [CATALOG[i][0] for i in ids],
            "acao_recomendada": _CTRL.sub(" ", out.acao_recomendada).strip(),
            "confianca": round((out.confianca + rule.confianca) / 2, 2),  # ancora na confiança das regras
            "mitre_attack": out.mitre_attack or rule.mitre_attack,
            "evidencias": [evidence[n] for n in lines if n in evidence],
            "justificativa": f"{rule.justificativa} | IA: {_CTRL.sub(' ', out.justificativa).strip()}",
            "fonte": "llm",
        })


def refine_or_fallback(analyzer: AIAnalyzer | None, rule: Finding, evidence: dict[int, str]) -> tuple[Finding, str | None]:
    """Nunca levanta: devolve (achado, erro_ia)."""
    if analyzer is None:
        return rule, None
    try:
        return analyzer.refine(rule, evidence), None
    except (LLMError, AIValidationError) as exc:
        log.warning("IA indisponível/inválida, usando regras: %s", exc)
        return rule, str(exc)
    except Exception as exc:  # defesa em profundidade: IA nunca derruba o pipeline
        log.exception("erro inesperado na IA")
        return rule, f"erro inesperado: {type(exc).__name__}"
