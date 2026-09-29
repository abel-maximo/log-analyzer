"""Estratégia:
- Classificação do IP (externo/interno/suspeito) é feita ANTES do mascaramento, sobre o dado bruto em memória.
- IP é mascarado para exibição (/16 IPv4, /32 IPv6) e referenciado por HMAC para agrupamento.
- Usuário é pseudonimizado via HMAC-SHA256 (determinístico, não reversível sem a chave).
- Após este módulo, o dado bruto é descartado.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
from datetime import datetime

from .config import Settings
from .models import NormalizedEvent, RawEvent

_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "::1/128", "fc00::/7", "fe80::/10")]
_PRIVATE_V4_PREFIXES =("10.", "127.", "192.168.", "169.254.") + tuple(f"172.{i}." for i in range(16, 32))


def _hmac(key: str, value: str, n: int = 10) -> str:
    return hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()[:n]


def classify_ip(ip: str | None) -> str:
    """external | internal | unknown. Aceita IPs já mascarados (ex.: 185.32.x.x)."""
    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
        if any(addr in n for n in _INTERNAL_NETS if n.version == addr.version):
            return "internal"
        if addr.is_multicast or addr.is_unspecified or addr.is_reserved:
            return "unknown"
        # Nota: faixas de documentação (RFC 5737) são tratadas como externas propositalmente.
        return "external"
    except ValueError:
        # IP parcialmente mascarado: heurística pelos octetos conhecidos
        if ip.startswith(_PRIVATE_V4_PREFIXES):
            return "internal"
        first = ip.split(".")[0]
        if first.isdigit() and 1 <= int(first) <= 223:
            return "external"
        return "unknown"


def is_suspicious(ip: str | None, cidrs: list[str]) -> bool:
    if not ip or not cidrs:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def mask_ip(ip: str | None) -> str | None:
    if not ip:
        return ip
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # já mascarado ou formato parcial: mantém apenas até 2 octetos numéricos
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(parts[:2] + ["x", "x"])
        return "x.x.x.x"
    if addr.version == 4:
        o = str(addr).split(".")
        return f"{o[0]}.{o[1]}.x.x"
    hextets = addr.exploded.split(":")
    return f"{hextets[0]}:{hextets[1]}:x:x:x:x:x:x"


def is_off_hours(ts: datetime, start: int, end: int) -> bool:
    return not (start <= ts.hour < end)


def anonymize(event: RawEvent, s: Settings) -> NormalizedEvent:
    key = s.pseudonym_key.get_secret_value()
    user_l = event.user.lower() if event.user else None
    privileged = bool(user_l and user_l in s.privileged_set)

    if event.user and s.mask_users:
        user_out = event.user if privileged else f"user_{_hmac(key, user_l)}"
    else:
        user_out = event.user

    success = {"LOGIN_SUCCESS": True, "LOGIN_FAILED": False}.get(event.event_type)
    return NormalizedEvent(
        line_no=event.line_no,
        timestamp=event.timestamp,
        event_type=event.event_type,
        user=user_out,
        ip=mask_ip(event.ip) if s.mask_ips else event.ip,
        ip_ref=_hmac(key, event.ip, 16) if event.ip else None,
        ip_scope=classify_ip(event.ip),
        ip_suspicious=is_suspicious(event.ip, s.suspicious_list),
        privileged=privileged,
        off_hours=is_off_hours(event.timestamp, s.business_hours_start, s.business_hours_end),
        success=success,
        metadata=dict(event.metadata),
    )
