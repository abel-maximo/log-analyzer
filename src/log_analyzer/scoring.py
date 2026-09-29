"""Cálculo de severidade explicável: score aditivo + pisos (overrides) documentados."""
from __future__ import annotations

from .models import Indicator, Severity

HIGH_THRESHOLD = 70
MEDIUM_THRESHOLD = 40


def score(indicators: list[Indicator]) -> int:
    return min(100, sum(i.peso for i in indicators))


def severity(indicators: list[Indicator]) -> tuple[Severity, int, str]:
    """Retorna (severidade, score, justificativa legível)."""
    ids = {i.id for i in indicators}
    s = score(indicators)
    if s >= HIGH_THRESHOLD:
        sev = Severity.ALTA
    elif s >= MEDIUM_THRESHOLD:
        sev = Severity.MEDIA
    else:
        sev = Severity.BAIXA

    reasons = [f"{i.descricao} (+{i.peso})" for i in indicators] or ["nenhum indicador de risco"]
    just = f"score={s} [" + ", ".join(reasons) + f"]; limiares: ALTA≥{HIGH_THRESHOLD}, MÉDIA≥{MEDIUM_THRESHOLD}"

    # Pisos: combinações que indicam comprometimento provável independem do score
    if "SUCCESS_AFTER_FAILURES" in ids and ids & {"PRIVILEGED_ACCOUNT", "EXTERNAL_IP", "SUSPICIOUS_IP"}:
        if sev is not Severity.ALTA:
            just += "; piso ALTA: sucesso após falhas em conta privilegiada/origem externa"
        sev = Severity.ALTA
    return sev, s, just


def confidence(indicators: list[Indicator], n_events: int) -> float:
    """Heurística (NÃO é probabilidade calibrada): mais indicadores e mais evidência => maior confiança."""
    base = 0.5 + 0.08 * len(indicators) + min(0.1, 0.02 * n_events)
    return round(min(0.95, base), 2)
