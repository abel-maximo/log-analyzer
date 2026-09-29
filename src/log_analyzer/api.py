"""API REST (FastAPI) + dashboard."""

import hashlib
import json
import hmac
import html
import logging
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, model_validator

from . import __version__
from .audit import audit
from .config import Settings, get_settings
from .db import Repository
from .ingest import IngestError, from_text
from .pipeline import Analyzer
from .report import render, to_json

log = logging.getLogger("log_analyzer.api")


class AnalyzeRequest(BaseModel):
    logs: str | None = Field(default=None, description="Texto com uma linha de log por linha")
    lines: list[str] | None = None
    use_llm: bool = True
    persist: bool = True

    @model_validator(mode="after")
    def _one_source(self):
        if not self.logs and not self.lines:
            raise ValueError("informe 'logs' ou 'lines'")
        return self


def create_app(settings: Settings | None = None, analyzer: Analyzer | None = None) -> FastAPI:
    s = settings or get_settings()
    repo = analyzer.repo if analyzer and analyzer.repo else Repository(s.database_url)
    engine = analyzer or Analyzer(s, repository=repo)
    if engine.repo is None:
        engine.repo = repo

    if s.api_key is None:
        if s.app_env == "prod":
            raise RuntimeError("API_KEY é obrigatória com APP_ENV=prod")
        log.warning("API_KEY não definida: autenticação DESABILITADA (apenas desenvolvimento)")

    app = FastAPI(title="AI Security Log Analyzer", version=__version__,
                  docs_url=None if s.app_env == "prod" else "/docs", redoc_url=None)

    def actor(x_api_key: Annotated[str | None, Header()] = None) -> str:
        if s.api_key is None:
            return "anonymous-dev"
        if not x_api_key or not hmac.compare_digest(x_api_key, s.api_key.get_secret_value()):
            audit(s.audit_log_path, "auth", "unknown", outcome="denied")
            raise HTTPException(status_code=401, detail="não autorizado")
        return "key:" + hashlib.sha256(x_api_key.encode()).hexdigest()[:8]  # nunca loga a chave

    Actor = Annotated[str, Depends(actor)]

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > 10 * 1024 * 1024:
            return JSONResponse({"detail": "payload muito grande"}, status_code=413)
        resp = await call_next(request)
        resp.headers.update({
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
        })
        if request.url.path == "/":
            resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
        return resp

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        log.exception("erro não tratado")
        return JSONResponse({"detail": "erro interno"}, status_code=500)  # sem stack trace ao cliente

    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__, "llm_configurado": s.llm_enabled}

    def _run(lines: list[str], who: str, use_llm: bool, persist: bool):
        try:
            return engine.analyze(lines, source="api", actor=who, use_llm=use_llm, persist=persist)
        except IngestError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc

    @app.post("/api/v1/analyze")
    def analyze(body: AnalyzeRequest, who: Actor):
        try:
            lines = body.lines if body.lines is not None else from_text(body.logs or "", s.max_lines_per_request)
        except IngestError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        if len(lines) > s.max_lines_per_request:
            raise HTTPException(status_code=413, detail="limite de linhas excedido")
        return JSONResponse(content=json.loads(to_json(_run(lines, who, body.use_llm, body.persist))))

    @app.post("/api/v1/analyze/raw", response_class=PlainTextResponse)
    async def analyze_raw(request: Request, who: Actor,
                          format: Literal["text", "json", "md"] = "text", use_llm: bool = True):
        text = (await request.body()).decode("utf-8", errors="replace")
        try:
            lines = from_text(text, s.max_lines_per_request)
        except IngestError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        return PlainTextResponse(render(_run(lines, who, use_llm, True), format))

    @app.get("/api/v1/analyses")
    def list_analyses(who: Actor, limit: int = Query(20, ge=1, le=500),
                      severidade: Literal["ALTA", "MÉDIA", "BAIXA"] | None = None):
        audit(s.audit_log_path, "list", who)
        return [{"id": r.id, "created_at": r.created_at, "severidade_geral": r.severidade_geral.value,
                 "total_eventos": r.total_eventos, "achados": len(r.analises)} for r in repo.list(limit, severidade)]

    @app.get("/api/v1/analyses/{analysis_id}/report")
    def get_report(analysis_id: str, who: Actor, format: Literal["text", "json", "md"] = "json"):
        r = repo.get(analysis_id)
        if not r:
            raise HTTPException(status_code=404, detail="análise não encontrada")
        audit(s.audit_log_path, "read", who, analysis_id=analysis_id)
        media = {"json": "application/json", "md": "text/markdown; charset=utf-8", "text": "text/plain; charset=utf-8"}
        return PlainTextResponse(render(r, format), media_type=media[format])

    @app.get("/", response_class=HTMLResponse)
    def dashboard(who: Actor):
        rows = repo.list(50)
        color = {"ALTA": "#c0392b", "MÉDIA": "#d68910", "BAIXA": "#1e8449"}
        trs = "".join(
            f"<tr><td>{html.escape(r.created_at.strftime('%Y-%m-%d %H:%M'))}</td>"
            f"<td style='color:{color[r.severidade_geral.value]};font-weight:600'>{r.severidade_geral.value}</td>"
            f"<td>{r.total_eventos}</td><td>{len(r.analises)}</td>"
            f"<td>{html.escape(r.analises[0].evento if r.analises else '—')}</td>"
            f"<td><code>{html.escape(r.id)}</code></td></tr>" for r in rows)
        counts = {k: sum(1 for r in rows if r.severidade_geral.value == k) for k in color}
        cards = "".join(f"<div class='c'><b style='color:{color[k]}'>{v}</b><span>{k}</span></div>" for k, v in counts.items())
        return f"""<!doctype html><html lang="pt-br"><meta charset="utf-8"><title>Log Analyzer</title>
<style>body{{font:14px system-ui;margin:24px;color:#222}}table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #ddd;padding:6px;text-align:left}}.k{{display:flex;gap:12px;margin:16px 0}}
.c{{border:1px solid #ddd;border-radius:8px;padding:12px 20px}}.c b{{font-size:24px;display:block}}</style>
<h1>AI Security Log Analyzer</h1><p>Últimas 50 análises (dados anonimizados)</p><div class="k">{cards}</div>
<table><tr><th>Data (UTC)</th><th>Severidade</th><th>Eventos</th><th>Achados</th><th>Principal evento</th><th>ID</th></tr>{trs}</table></html>"""

    return app


def app_factory() -> FastAPI:  # uvicorn --factory log_analyzer.api:app_factory
    logging.basicConfig(level=logging.INFO)
    return create_app()
