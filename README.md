# AI Security Log Analyzer

Sistema para análise automatizada de logs de segurança: detecta força bruta, password spraying, força bruta distribuída e autenticações suspeitas, atribui severidade explicável (ALTA / MÉDIA / BAIXA), mapeia para MITRE ATT&CK e recomenda ações. Usa **regras determinísticas como fonte da verdade** e um **LLM opcional** para refinar classificação e explicação, sempre sob validação estrita e com fallback automático.

## Estrutura

```
ai-security-log-analyzer/
├── src/log_analyzer/
│   ├── config.py      # Settings via .env (pydantic-settings)
│   ├── models.py      # Schemas de domínio
│   ├── ingest.py      # Arquivo / stdin / texto
│   ├── parser.py      # Parsing + normalização + redação de credenciais
│   ├── privacy.py     # Máscara de IP, pseudonimização HMAC, classificação de IP
│   ├── features.py    # Sessionização e features
│   ├── rules.py       # Indicadores, classificação, allowlist MITRE
│   ├── scoring.py     # Score, severidade, confiança
│   ├── ai/            # providers.py, prompt.py, analyzer.py (guardrails)
│   ├── pipeline.py    # Orquestração
│   ├── db.py          # SQLAlchemy (SQLite/PostgreSQL)
│   ├── audit.py       # Auditoria JSON Lines
│   ├── report.py      # texto / JSON / Markdown
│   ├── api.py         # FastAPI + dashboard
│   └── cli.py         # log-analyzer
├── tests/             # 40 testes (unitários + integração)
├── examples/          # entradas e saídas de exemplo
├── docs/              # ARCHITECTURE.md, ROADMAP.md
├── Dockerfile, docker-compose.yml, .env.example, .github/workflows/ci.yml
```

## Execução

### Docker

```bash
cp .env.example .env
# defina API_KEY e PSEUDONYM_KEY no .env
docker compose up --build -d
curl -s localhost:8000/health
```

Com PostgreSQL: defina `DATABASE_URL=postgresql+psycopg://analyzer:analyzer@db:5432/analyzer` no `.env` e rode `docker compose --profile postgres up --build -d`.

### Local

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt && pip install --no-deps -e .
cp .env.example .env
pytest
```

## CLI

```bash
log-analyzer analyze examples/sample.log                 # texto
log-analyzer analyze examples/sample.log -f json         # JSON
log-analyzer analyze examples/mixed.log -f md -o rel.md  # Markdown
cat auth.log | log-analyzer analyze - --no-llm           # stdin, só regras
log-analyzer analyze auth.log --fail-on ALTA             # exit 2 se houver ALTA (cron/CI)
log-analyzer list
log-analyzer show <id> -f md
```

## API

| Método | Rota | Descrição |
|---|---|---|
| GET | `/health` | Status |
| POST | `/api/v1/analyze` | JSON `{"logs": "...", "use_llm": true, "persist": true}` |
| POST | `/api/v1/analyze/raw?format=text\|json\|md` | Corpo `text/plain` |
| GET | `/api/v1/analyses?limit=&severidade=` | Lista análises |
| GET | `/api/v1/analyses/{id}/report?format=` | Relatório |
| GET | `/` | Dashboard HTML |
| GET | `/docs` | OpenAPI (desativado com `APP_ENV=prod`) |

Autenticação: header `X-API-Key`. Sem `API_KEY` a auth fica desabilitada **apenas** em dev; com `APP_ENV=prod` a aplicação não sobe sem ela.

```bash
curl -s -X POST localhost:8000/api/v1/analyze \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"logs":"2026-09-29 14:32 LOGIN_FAILED user=admin ip=185.32.x.x\n2026-09-29 14:32 LOGIN_FAILED user=admin ip=185.32.x.x\n2026-09-29 14:33 LOGIN_FAILED user=admin ip=185.32.x.x\n2026-09-29 14:34 LOGIN_SUCCESS user=admin ip=185.32.x.x"}'
```

## Exemplo

Entrada (`examples/sample.log`):

```
2026-09-29 14:32 LOGIN_FAILED user=admin ip=185.32.x.x
2026-09-29 14:32 LOGIN_FAILED user=admin ip=185.32.x.x
2026-09-29 14:33 LOGIN_FAILED user=admin ip=185.32.x.x
2026-09-29 14:34 LOGIN_SUCCESS user=admin ip=185.32.x.x
```

Saída (`log-analyzer analyze examples/sample.log --no-llm`):

```
Severidade: ALTA

Evento identificado:
Possível ataque de força bruta seguido de autenticação bem-sucedida.

Indicadores:
- múltiplas tentativas de login
- mesmo endereço IP
- conta administrativa
- autenticação bem-sucedida após falhas
- IP externo

Ação recomendada:
Investigar a origem do IP e revisar a atividade da conta; considerar redefinição de credenciais, revogação de sessões ativas e verificação de MFA.

Confiança: 0.95 | MITRE ATT&CK: T1110, T1078 | Fonte: regras
Justificativa: score=95 [múltiplas tentativas de login (+20), mesmo endereço IP (+10), conta administrativa (+20), autenticação bem-sucedida após falhas (+35), IP externo (+10)]; limiares: ALTA≥70, MÉDIA≥40
```

JSON completo em `examples/sample_output.json`. Cenário com ALTA, MÉDIA e BAIXA em `examples/mixed.log` → `examples/mixed_report.md`.

## Habilitando o LLM

```env
LLM_PROVIDER=anthropic          # ou openai (qualquer endpoint /v1/chat/completions)
LLM_API_KEY=...
LLM_MODEL=<id do modelo conforme a documentação do provedor>
LLM_BASE_URL=                   # ex.: http://ollama:11434 para modelo local
```

Sem essas variáveis — ou em caso de timeout/erro/saída inválida — o sistema usa as regras. O LLM recebe apenas dados mascarados. Detalhes dos guardrails em [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Formato de log suportado

`YYYY-MM-DD HH:MM[:SS] EVENTO chave=valor ...` — aceita `T` como separador, `user`/`username`, `ip`/`src_ip`/`source_ip` e aliases (`LOGIN_FAILURE`, `AUTH_FAILED`, `LOGIN_OK`…). Linhas inválidas são reportadas em `erros_parsing` e ignoradas.

