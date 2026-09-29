"""Regras + scoring: cobre ALTA, MÉDIA e BAIXA."""
from log_analyzer.models import Severity


def _run(analyzer, text):
    return analyzer.analyze(text.strip().splitlines(), persist=False, use_llm=False)


def test_example_is_alta_brute_force_followed_by_success(analyzer, example_lines):
    r = analyzer.analyze(example_lines, persist=False, use_llm=False)
    assert r.severidade_geral is Severity.ALTA
    f = r.analises[0]
    assert "força bruta" in f.evento and "bem-sucedida" in f.evento
    for ind in ("múltiplas tentativas de login", "mesmo endereço IP", "conta administrativa",
                "autenticação bem-sucedida após falhas"):
        assert ind in f.indicadores
    assert "Investigar a origem do IP" in f.acao_recomendada and "revisar a atividade da conta" in f.acao_recomendada
    assert f.mitre_attack == ["T1110", "T1078"]
    assert 0.9 <= f.confianca <= 0.95
    assert "score=" in f.justificativa and len(f.evidencias) == 4


def test_media_failures_on_admin_without_success(analyzer):
    r = _run(analyzer, """
2026-09-29 14:32 LOGIN_FAILED user=admin ip=185.32.1.1
2026-09-29 14:33 LOGIN_FAILED user=admin ip=185.32.1.1
2026-09-29 14:34 LOGIN_FAILED user=admin ip=185.32.1.1""")
    assert r.severidade_geral is Severity.MEDIA
    assert r.analises[0].mitre_attack == ["T1110.001"]


def test_baixa_single_failure_internal(analyzer):
    r = _run(analyzer, "2026-09-29 10:00 LOGIN_FAILED user=maria ip=10.0.0.5")
    assert r.severidade_geral is Severity.BAIXA
    assert r.analises[0].evento == "Falha de autenticação isolada"


def test_normal_success_produces_no_finding(analyzer):
    r = _run(analyzer, "2026-09-29 10:00 LOGIN_SUCCESS user=maria ip=8.8.8.8")
    assert r.analises == [] and r.severidade_geral is Severity.BAIXA


def test_off_hours_success_from_suspicious_ip(analyzer):
    r = _run(analyzer, "2026-09-29 03:10 LOGIN_SUCCESS user=maria ip=203.0.113.7")
    f = r.analises[0]
    assert {"OFF_HOURS", "SUSPICIOUS_IP", "EXTERNAL_IP"} <= set(f.indicadores_ids)
    assert f.mitre_attack == ["T1078"]


def test_password_spraying_detected_and_deduplicated(analyzer):
    lines = [f"2026-09-29 14:{30 + i:02d} LOGIN_FAILED user=u{i} ip=198.51.100.7" for i in range(6)]
    r = analyzer.analyze(lines, persist=False, use_llm=False)
    assert r.severidade_geral is Severity.ALTA
    assert len(r.analises) == 1 
    assert r.analises[0].mitre_attack == ["T1110.003"]


def test_window_splits_sessions(analyzer):
    r = _run(analyzer, """
2026-09-29 14:00 LOGIN_FAILED user=admin ip=185.32.1.1
2026-09-29 14:01 LOGIN_FAILED user=admin ip=185.32.1.1
2026-09-29 16:00 LOGIN_FAILED user=admin ip=185.32.1.1
2026-09-29 16:01 LOGIN_SUCCESS user=admin ip=185.32.1.1""")
    # falhas separadas por > WINDOW_MINUTES não compõem força bruta
    assert all("SUCCESS_AFTER_FAILURES" not in f.indicadores_ids for f in r.analises)


def test_different_ips_same_mask_not_merged(analyzer):
    r = _run(analyzer, """
2026-09-29 14:32 LOGIN_FAILED user=admin ip=185.32.1.1
2026-09-29 14:33 LOGIN_FAILED user=admin ip=185.32.2.2
2026-09-29 14:34 LOGIN_FAILED user=admin ip=185.32.3.3""")
    # agrupamento por HMAC do IP real => detectado como ataque distribuído
    assert len(r.analises) == 1
    f = r.analises[0]
    assert "DISTRIBUTED_FAILURES" in f.indicadores_ids and "SAME_IP" not in f.indicadores_ids
    assert r.severidade_geral is Severity.ALTA  # admin + externo + distribuído
