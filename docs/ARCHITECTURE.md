# Arquitetura — AI Security Log Analyzer

## Visão geral do pipeline

```
 ingest ─► parser ─► privacy ─► features ─► rules ─► scoring ─► ai (opcional) ─► validação ─► db / report / audit
 (arquivo,  (regex,   (máscara,  (sessões,   (indic.   (score +   (LLM refina)     (guardrails;     (SQLite/PG,
  stdin,    normaliza, HMAC,     janelas)    determ.)  pisos)                       falha → regras)  txt/json/md)
  API)      redige     classif.
            segredos)  de IP)
```

| Módulo | Responsabilidade | Decisão técnica |
|---|---|---|
| `ingest.py` | Arquivo, stdin, texto da API | Limite de linhas (`MAX_LINES_PER_REQUEST`) contra DoS |
| `parser.py` | Regex + chave=valor, aliases de evento | Linha ruim vira `ParseError`, nunca derruba a análise. Charset restrito em `user`/`ip` (mitiga prompt injection). Chaves `password/token/secret…` → `[REDACTED]` |
| `privacy.py` | Classificação de IP, máscara, pseudonimização | Classifica **antes** de mascarar; agrupa por HMAC do IP real (não pela máscara `/16`, que fundiria atacantes distintos) |
| `features.py` | Sessões por janela de inatividade | 3 visões: `account` (IP+usuário), `source` (IP → spraying), `target` (usuário → força bruta distribuída) |
| `rules.py` | Regras puras `GroupFeatures → Indicator` | Catálogo fechado de indicadores e allowlist MITRE: a IA não pode sair desse vocabulário |
| `scoring.py` | Score aditivo + pisos | Explicável: cada ponto tem origem; piso ALTA para “sucesso após falhas” em conta privilegiada/origem externa |
| `ai/` | Provedores HTTP (Anthropic, OpenAI-compatível), prompt, validação | Sem SDK (menos dependências). Guardrails em `analyzer.validate` |
| `pipeline.py` | Orquestração | Injeção de dependências (LLM, repositório) → testável sem rede |
| `db.py` | SQLAlchemy 2.x | Persiste só eventos normalizados/mascarados; `lazy="raise"` evita carregamento acidental |
| `report.py` | Texto, JSON, Markdown | JSON segue o contrato do enunciado + bloco `explicacao` |
| `api.py` | FastAPI + dashboard HTML | API key (comparação em tempo constante), headers de segurança, CSP, erros sem stack trace |
| `cli.py` | argparse | `--fail-on` retorna exit code 2 (integra com cron/CI/SOAR) |
| `audit.py` | JSON Lines rotativo | Registra quem/quando/resultado — nunca conteúdo de log |

## Modelo de dados

**Evento normalizado** (`NormalizedEvent`): `timestamp, event_type, user (pseudônimo), ip (mascarado), ip_ref (HMAC), ip_scope, ip_suspicious, privileged, off_hours, success, metadata`.

**Análise** (`Finding`): `severidade, evento, indicadores, acao_recomendada, confianca, mitre_attack, evidencias` + explicabilidade (`score, indicadores_ids, justificativa, fonte`).

Tabelas: `analyses` (1) ─< `findings` (N) e `analyses` (1) ─< `events` (N).

## Indicadores e pesos

| ID | Descrição | Peso |
|---|---|---|
| MULTIPLE_FAILURES | ≥ `FAILURE_THRESHOLD` falhas na sessão | 20 |
| SAME_IP | falhas de um único IP | 10 |
| PRIVILEGED_ACCOUNT | conta em `PRIVILEGED_ACCOUNTS` | 20 |
| SUCCESS_AFTER_FAILURES | sucesso após sequência de falhas ≥ limiar | 35 |
| OFF_HOURS | fora de `BUSINESS_HOURS_START..END` | 10 |
| EXTERNAL_IP | IP fora de RFC1918/loopback/CGNAT/ULA | 10 |
| SUSPICIOUS_IP | IP em `SUSPICIOUS_IPS` (CIDR) | 25 |
| PASSWORD_SPRAYING | ≥ `SPRAY_USER_THRESHOLD` contas com falha, mesmo IP | 30 |
| HIGH_VELOCITY | ≥ 5 falhas/min | 10 |
| DISTRIBUTED_FAILURES | falhas na mesma conta a partir de >1 IP | 25 |

Severidade: **ALTA ≥ 70**, **MÉDIA ≥ 40**, senão **BAIXA** (+ pisos). Exemplo do enunciado: 20+10+20+35+10 = **95 → ALTA**.

Mapeamento MITRE ATT&CK: T1110 (Brute Force), T1110.001 (Password Guessing), T1110.003 (Password Spraying), T1078 (Valid Accounts).

## Pipeline de IA e guardrails

1. Regras geram o achado base (sempre).
2. Se `LLM_PROVIDER≠none` e há indicadores, envia **somente** contexto estruturado + linhas de evidência já anonimizadas, delimitadas em `<dados_log>` e marcadas como não confiáveis.
3. Resposta validada por schema pydantic e por regras de negócio:
   - `indicadores_ids ⊆ indicadores detectados` (IA não inventa indicador);
   - `mitre_attack ⊆ allowlist`;
   - `evidencias_linhas ⊆ linhas reais do grupo`;
   - severidade **nunca rebaixada** e escalada em no máximo 1 nível.
4. Qualquer falha (timeout, JSON inválido, violação) → achado das regras (`fonte="regras"`) e contagem em `ai_errors` na auditoria.

**Por que a IA não pode rebaixar?** Um atacante controla parte do conteúdo do log. Se o LLM pudesse reduzir a severidade, uma injeção de prompt bem-sucedida esconderia o ataque. Escalar é seguro (no pior caso, falso positivo).

## Privacidade (LGPD)

- Minimização: linha bruta não é persistida; IP completo e usuário real não saem do módulo `privacy`.
- Pseudonimização (art. 13, §4º) via HMAC-SHA256 com `PSEUDONYM_KEY`: permite correlação sem reidentificação sem a chave.
- Contas privilegiadas genéricas (`admin`, `root`) ficam legíveis — não identificam pessoa natural e são essenciais para a triagem.
- Credenciais em campos conhecidos são redigidas no parser.
- Envio ao LLM (operador/terceiro) contém apenas dados mascarados; avalie DPA com o provedor.
- Retenção: não implementada no MVP (ver roadmap).

## Decisões e trade-offs

| Decisão | Alternativa | Por quê |
|---|---|---|
| Regras como fonte da verdade + LLM como refinamento | LLM decide tudo | Determinismo, auditabilidade, funcionamento offline, custo previsível |
| Sessionização por inatividade | Janela fixa (tumbling) | Não corta um ataque ao meio na borda da janela |
| HTTP direto aos provedores | SDKs oficiais | Menos dependências; fácil trocar para modelo local (Ollama/vLLM) |
| SQLite padrão | Postgres obrigatório | Zero setup para o MVP; Postgres via `DATABASE_URL` |
| `create_all` | Alembic | Simplicidade no MVP; migrations no roadmap |
