"""Integração: pipeline + DB + auditoria + API + CLI."""
import json

import pytest
from pydantic import SecretStr
from fastapi.testclient import TestClient

from log_analyzer import cli
from log_analyzer.api import create_app
from log_analyzer.config import Settings, get_settings
from log_analyzer.report import to_markdown, to_text


def test_persistence_roundtrip_without_raw_data(analyzer, repo):
    lines = ["2026-09-29 14:32 LOGIN_FAILED user=joao ip=185.32.10.4 password=segredo"] * 3 + \
            ["2026-09-29 14:34 LOGIN_SUCCESS user=joao ip=185.32.10.4"]
    r = analyzer.analyze(lines)
    got = repo.get(r.id)
    assert got and got.severidade_geral == r.severidade_geral and got.analises[0].evento == r.analises[0].evento
    dump = got.model_dump_json()
    assert "185.32.10.4" not in dump and "joao" not in dump and "segredo" not in dump
    assert repo.list(10)[0].id == r.id


def test_audit_log_written_without_log_content(analyzer, settings, example_lines):
    analyzer.analyze(example_lines, actor="tester")
    rec = json.loads(open(settings.audit_log_path, encoding="utf-8").read().splitlines()[-1])
    assert rec["action"] == "analyze" and rec["actor"] == "tester" and rec["severity"] == "ALTA"
    assert "admin" not in json.dumps(rec) and "185.32" not in json.dumps(rec)


def test_reports_render(analyzer, example_lines):
    r = analyzer.analyze(example_lines, persist=False)
    txt = to_text(r)
    assert txt.startswith("Severidade: ALTA") and "Evento identificado:" in txt and "Ação recomendada:" in txt
    assert "## Achado 1 — ALTA" in to_markdown(r)


@pytest.fixture
def client(settings, analyzer):
    settings.api_key = SecretStr("s3cret")
    return TestClient(create_app(settings, analyzer))


H = {"X-API-Key": "s3cret"}


def test_api_requires_key(client):
    assert client.post("/api/v1/analyze", json={"logs": "x"}).status_code == 401
    assert client.post("/api/v1/analyze", json={"logs": "x"}, headers={"X-API-Key": "errada"}).status_code == 401
    assert client.get("/health").status_code == 200


def test_empty_api_key_allows_dashboard(analyzer):
    settings = Settings(_env_file=None, app_env="dev", api_key="")
    client = TestClient(create_app(settings, analyzer))
    assert settings.api_key is None
    assert client.get("/").status_code == 200


def test_api_analyze_example(client, example_lines):
    resp = client.post("/api/v1/analyze", json={"logs": "\n".join(example_lines)}, headers=H)
    assert resp.status_code == 200
    body = resp.json()
    assert body["severidade_geral"] == "ALTA"
    a = body["analises"][0]
    assert set(a) >= {"severidade", "evento", "indicadores", "acao_recomendada", "confianca", "mitre_attack"}
    assert resp.headers["X-Content-Type-Options"] == "nosniff"

    rid = body["id"]
    assert client.get(f"/api/v1/analyses/{rid}/report?format=md", headers=H).text.startswith("# Relatório")
    assert any(x["id"] == rid for x in client.get("/api/v1/analyses", headers=H).json())
    assert client.get("/api/v1/analyses/nao-existe/report", headers=H).status_code == 404
    assert "ALTA" in client.get("/", headers=H).text


def test_api_raw_text_and_validation(client, example_lines):
    r = client.post("/api/v1/analyze/raw?format=text", content="\n".join(example_lines), headers=H)
    assert r.status_code == 200 and r.text.startswith("Severidade: ALTA")
    assert client.post("/api/v1/analyze", json={}, headers=H).status_code == 422


def test_api_line_limit(client, settings):
    settings.max_lines_per_request = 2
    r = client.post("/api/v1/analyze", json={"logs": "a\nb\nc"}, headers=H)
    assert r.status_code == 413


def test_prod_without_api_key_refuses_to_start(settings, analyzer):
    settings.app_env = "prod"
    with pytest.raises(RuntimeError):
        create_app(settings, analyzer)


def test_cli_analyze_json_and_fail_on(tmp_path, monkeypatch, capsys, example_lines):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/cli.db")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.log"))
    monkeypatch.setenv("LLM_PROVIDER", "none")
    get_settings.cache_clear()
    f = tmp_path / "in.log"
    f.write_text("\n".join(example_lines), encoding="utf-8")

    assert cli.main(["analyze", str(f), "--format", "json", "--no-llm"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["severidade_geral"] == "ALTA"

    assert cli.main(["analyze", str(f), "--no-llm", "--fail-on", "ALTA"]) == 2
    capsys.readouterr()
    assert cli.main(["list"]) == 0 and "ALTA" in capsys.readouterr().out
    assert cli.main(["analyze", str(tmp_path / "nao-existe.log")]) == 1
    get_settings.cache_clear()
