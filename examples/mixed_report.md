# Relatório — AI Security Log Analyzer

- **ID:** `c2a52cbe-e934-4fd5-924d-d46861a7e341`
- **Gerado em:** 2026-09-29 20:17:32 UTC
- **Severidade geral:** **ALTA**
- **Linhas / eventos válidos:** 11 / 10
- **LLM utilizado:** não (regras)

## Resumo

| # | Severidade | Evento | Confiança | MITRE |
|---|---|---|---|---|
| 1 | ALTA | Possível ataque de força bruta seguido de autenticação bem-sucedida | 0.95 | T1110, T1078 |
| 2 | MÉDIA | Possível tentativa de força bruta sem autenticação bem-sucedida | 0.88 | T1110.001 |
| 3 | BAIXA | Falha de autenticação isolada | 0.54 | - |

## Achado 1 — ALTA

**Evento:** Possível ataque de força bruta seguido de autenticação bem-sucedida

**Indicadores:**

- múltiplas tentativas de login
- mesmo endereço IP
- conta administrativa
- autenticação bem-sucedida após falhas
- IP externo

**Ação recomendada:** Investigar a origem do IP e revisar a atividade da conta; considerar redefinição de credenciais, revogação de sessões ativas e verificação de MFA

**MITRE ATT&CK:**

- T1110 — Brute Force
- T1078 — Valid Accounts

**Explicabilidade:** score=95 [múltiplas tentativas de login (+20), mesmo endereço IP (+10), conta administrativa (+20), autenticação bem-sucedida após falhas (+35), IP externo (+10)]; limiares: ALTA≥70, MÉDIA≥40

**Evidências (anonimizadas):**

```
L2: 2026-09-29 14:32 LOGIN_FAILED user=admin ip=185.32.x.x
L3: 2026-09-29 14:32 LOGIN_FAILED user=admin ip=185.32.x.x
L4: 2026-09-29 14:33 LOGIN_FAILED user=admin ip=185.32.x.x
L5: 2026-09-29 14:34 LOGIN_SUCCESS user=admin ip=185.32.x.x
```

## Achado 2 — MÉDIA

**Evento:** Possível tentativa de força bruta sem autenticação bem-sucedida

**Indicadores:**

- múltiplas tentativas de login
- mesmo endereço IP
- conta administrativa
- IP externo

**Ação recomendada:** Monitorar o IP de origem, avaliar bloqueio temporário e confirmar a atividade com o responsável pela conta

**MITRE ATT&CK:**

- T1110.001 — Brute Force: Password Guessing

**Explicabilidade:** score=60 [múltiplas tentativas de login (+20), mesmo endereço IP (+10), conta administrativa (+20), IP externo (+10)]; limiares: ALTA≥70, MÉDIA≥40

**Evidências (anonimizadas):**

```
L6: 2026-09-29 09:10 LOGIN_FAILED user=root ip=45.12.x.x
L7: 2026-09-29 09:11 LOGIN_FAILED user=root ip=45.12.x.x
L8: 2026-09-29 09:11 LOGIN_FAILED user=root ip=45.12.x.x
```

## Achado 3 — BAIXA

**Evento:** Falha de autenticação isolada

**Indicadores:**

- (nenhum)

**Ação recomendada:** Nenhuma ação imediata; manter monitoramento

**MITRE ATT&CK:**

- n/a

**Explicabilidade:** score=0 [nenhum indicador de risco]; limiares: ALTA≥70, MÉDIA≥40

**Evidências (anonimizadas):**

```
L9: 2026-09-29 11:00 LOGIN_FAILED user=user_4999abbe1c ip=10.0.x.x
L10: 2026-09-29 11:01 LOGIN_SUCCESS user=user_4999abbe1c ip=10.0.x.x
```

## Linhas ignoradas

- L12: formato não reconhecido
