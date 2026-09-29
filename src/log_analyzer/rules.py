"""Regras determinísticas de segurança (fonte da verdade e fallback da IA).

Cada regra é pura: GroupFeatures -> Indicator | None. Isso torna cada decisão
rastreável (explicabilidade) e testável isoladamente.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .features import GroupFeatures
from .models import Indicator

# Catálogo fechado: a IA só pode citar IDs daqui
CATALOG: dict[str, tuple[str, int]] = {
    "MULTIPLE_FAILURES": ("múltiplas tentativas de login", 20),
    "SAME_IP": ("mesmo endereço IP", 10),
    "PRIVILEGED_ACCOUNT": ("conta administrativa", 20),
    "SUCCESS_AFTER_FAILURES": ("autenticação bem-sucedida após falhas", 35),
    "OFF_HOURS": ("horário incomum", 10),
    "EXTERNAL_IP": ("IP externo", 10),
    "SUSPICIOUS_IP": ("IP presente em lista de suspeitos", 25),
    "PASSWORD_SPRAYING": ("múltiplas contas testadas a partir do mesmo IP", 30),
    "HIGH_VELOCITY": ("alta taxa de tentativas por minuto", 10),
    "DISTRIBUTED_FAILURES": ("falhas na mesma conta a partir de múltiplos IPs", 25),
}

AGGREGATE_INDICATORS = {"PASSWORD_SPRAYING", "DISTRIBUTED_FAILURES"}

# Técnicas MITRE ATT&CK permitidas nas saídas (allowlist)
MITRE_ALLOWED = {
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1078": "Valid Accounts",
}


def _ind(id_: str) -> Indicator:
    desc, weight = CATALOG[id_]
    return Indicator(id=id_, descricao=desc, peso=weight)


@dataclass(frozen=True)
class RuleConfig:
    failure_threshold: int = 3
    spray_user_threshold: int = 5
    velocity_per_minute: float = 5.0


Rule = Callable[[GroupFeatures, RuleConfig], Indicator | None]


def r_multiple_failures(f: GroupFeatures, c: RuleConfig):
    return _ind("MULTIPLE_FAILURES") if f.n_failures >= c.failure_threshold else None


def r_same_ip(f: GroupFeatures, c: RuleConfig):
    return _ind("SAME_IP") if f.n_failures >= c.failure_threshold and f.distinct_ips == 1 else None


def r_privileged(f: GroupFeatures, c: RuleConfig):
    return _ind("PRIVILEGED_ACCOUNT") if f.privileged else None


def r_success_after_failures(f: GroupFeatures, c: RuleConfig):
    return _ind("SUCCESS_AFTER_FAILURES") if f.success_after_failures else None


def r_off_hours(f: GroupFeatures, c: RuleConfig):
    return _ind("OFF_HOURS") if f.off_hours_events > 0 else None


def r_external_ip(f: GroupFeatures, c: RuleConfig):
    return _ind("EXTERNAL_IP") if f.ip_scope == "external" else None


def r_suspicious_ip(f: GroupFeatures, c: RuleConfig):
    return _ind("SUSPICIOUS_IP") if f.ip_suspicious else None


def r_password_spraying(f: GroupFeatures, c: RuleConfig):
    users_failed = len({e.user for e in f.events if e.success is False})
    return _ind("PASSWORD_SPRAYING") if f.kind == "source" and users_failed >= c.spray_user_threshold else None


def r_high_velocity(f: GroupFeatures, c: RuleConfig):
    return _ind("HIGH_VELOCITY") if f.n_failures >= c.failure_threshold and f.failures_per_minute >= c.velocity_per_minute else None


def r_distributed(f: GroupFeatures, c: RuleConfig):
    ips_failed = len({e.ip_ref for e in f.events if e.success is False})
    return (_ind("DISTRIBUTED_FAILURES")
            if f.kind == "target" and f.n_failures >= c.failure_threshold and ips_failed > 1 else None)


RULES: list[Rule] = [
    r_multiple_failures, r_same_ip, r_privileged, r_success_after_failures,
    r_off_hours, r_external_ip, r_suspicious_ip, r_password_spraying, r_high_velocity, r_distributed,
]


def evaluate(f: GroupFeatures, c: RuleConfig) -> list[Indicator]:
    return [i for rule in RULES if (i := rule(f, c)) is not None]


@dataclass(frozen=True)
class Classification:
    evento: str
    acao: str
    mitre: list[str]


def classify(ids: set[str], f: GroupFeatures) -> Classification:
    """Classificação determinística do evento a partir dos indicadores."""
    if "PASSWORD_SPRAYING" in ids:
        return Classification(
            "Possível password spraying: múltiplas contas testadas a partir do mesmo IP",
            "Investigar a origem do IP, avaliar bloqueio/rate limit e verificar se alguma conta-alvo autenticou com sucesso",
            ["T1110.003"],
        )
    if "SUCCESS_AFTER_FAILURES" in ids:
        acao = "Investigar a origem do IP e revisar a atividade da conta"
        if "PRIVILEGED_ACCOUNT" in ids:
            acao += "; considerar redefinição de credenciais, revogação de sessões ativas e verificação de MFA"
        return Classification(
            "Possível ataque de força bruta seguido de autenticação bem-sucedida", acao, ["T1110", "T1078"])
    if "DISTRIBUTED_FAILURES" in ids:
        return Classification(
            "Possível força bruta distribuída: falhas na mesma conta a partir de múltiplos IPs",
            "Investigar as origens dos IPs, avaliar bloqueio temporário da conta e revisar sua atividade",
            ["T1110"],
        )
    if "MULTIPLE_FAILURES" in ids:
        return Classification(
            "Possível tentativa de força bruta sem autenticação bem-sucedida",
            "Monitorar o IP de origem, avaliar bloqueio temporário e confirmar a atividade com o responsável pela conta",
            ["T1110.001"],
        )
    if f.n_successes and ("OFF_HOURS" in ids or "SUSPICIOUS_IP" in ids):
        return Classification(
            "Autenticação bem-sucedida em contexto incomum",
            "Confirmar a legitimidade do acesso com o responsável pela conta e revisar a sessão",
            ["T1078"],
        )
    return Classification(
        "Falha de autenticação isolada", "Nenhuma ação imediata; manter monitoramento", [])


def should_report(f: GroupFeatures, ids: set[str]) -> bool:
    """Evita ruído: sucesso normal (mesmo externo) não vira achado."""
    if f.kind == "source":
        return "PASSWORD_SPRAYING" in ids
    if f.kind == "target":
        return "DISTRIBUTED_FAILURES" in ids
    return f.n_failures > 0 or bool(ids & {"OFF_HOURS", "SUSPICIOUS_IP"})
