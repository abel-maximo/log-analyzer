"""IA: saída válida é aceita; qualquer violação cai no fallback de regras."""
import json

import pytest

from log_analyzer.ai import StaticLLM
from log_analyzer.ai.providers import LLMError
from log_analyzer.models import Severity
from log_analyzer.pipeline import Analyzer

VALID = {
    "severidade": "ALTA",
    "evento": "Possível ataque de força bruta seguido de autenticação bem-sucedida",
    "indicadores_ids": ["MULTIPLE_FAILURES", "SAME_IP", "PRIVILEGED_ACCOUNT", "SUCCESS_AFTER_FAILURES"],
    "acao_recomendada": "Investigar a origem do IP e revisar a atividade da conta",
    "confianca": 0.9,
    "mitre_attack": ["T1110", "T1078"],
    "evidencias_linhas": [1, 2, 3, 4],
    "justificativa": "3 falhas seguidas de sucesso na conta admin",
}


def _run(settings, repo, lines, response):
    llm = StaticLLM(response)
    r = Analyzer(settings, llm=llm, repository=repo).analyze(lines, persist=False)
    return r, llm


def test_valid_llm_output_is_used(settings, repo, example_lines):
    r, llm = _run(settings, repo, example_lines, "```json\n" + json.dumps(VALID, ensure_ascii=False) + "\n```")
    f = r.analises[0]
    assert r.llm_utilizado and f.fonte == "llm"
    assert "IP externo" not in f.indicadores  # IA pode omitir indicadores, nunca criar
    assert "IA:" in f.justificativa
    # privacidade: a IA só recebe dados mascarados/pseudonimizados
    system, user = llm.calls[0]
    assert "<dados_log>" in user and "185.32.x.x" in user


@pytest.mark.parametrize("patch,desc", [
    ({"indicadores_ids": ["MULTIPLE_FAILURES", "MALWARE_DETECTED"]}, "indicador inventado"),
    ({"mitre_attack": ["T1566"]}, "MITRE fora da allowlist"),
    ({"evidencias_linhas": [1, 99]}, "evidência inexistente"),
    ({"severidade": "BAIXA"}, "rebaixamento"),
    ({"confianca": 7}, "schema inválido"),
])
def test_invalid_llm_output_falls_back_to_rules(settings, repo, example_lines, patch, desc):
    r, _ = _run(settings, repo, example_lines, json.dumps({**VALID, **patch}))
    f = r.analises[0]
    assert f.fonte == "regras", desc
    assert f.severidade is Severity.ALTA and not r.llm_utilizado


def test_escalation_one_level_accepted(settings, repo):
    lines = [f"2026-09-29 14:3{i} LOGIN_FAILED user=admin ip=185.32.1.1" for i in range(3)]  # MÉDIA
    resp = {**VALID, "indicadores_ids": ["MULTIPLE_FAILURES", "PRIVILEGED_ACCOUNT"], "evidencias_linhas": [1, 2, 3],
            "mitre_attack": ["T1110.001"]}
    r, _ = _run(settings, repo, lines, json.dumps(resp))
    assert r.analises[0].fonte == "llm" and r.severidade_geral is Severity.ALTA


def test_escalation_two_levels_rejected(settings, repo):
    lines = ["2026-09-29 10:00 LOGIN_FAILED user=maria ip=185.32.1.1"]  # BAIXA (só IP externo)
    resp = {**VALID, "indicadores_ids": ["EXTERNAL_IP"], "evidencias_linhas": [1]}
    r, _ = _run(settings, repo, lines, json.dumps(resp))
    assert r.analises[0].fonte == "regras" and r.severidade_geral is Severity.BAIXA


def test_llm_error_and_garbage_fall_back(settings, repo, example_lines):
    for resp in (LLMError("timeout"), "não sei responder", RuntimeError("boom")):
        r, _ = _run(settings, repo, example_lines, resp)
        assert r.analises[0].fonte == "regras" and r.severidade_geral is Severity.ALTA


def test_no_llm_flag_skips_ai(settings, repo, example_lines):
    llm = StaticLLM(json.dumps(VALID))
    Analyzer(settings, llm=llm, repository=repo).analyze(example_lines, persist=False, use_llm=False)
    assert llm.calls == []
