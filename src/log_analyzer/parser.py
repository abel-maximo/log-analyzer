"""Parsing e normalização de logs textuais.

Formato suportado (chave=valor após o tipo do evento):
    2026-09-29 14:32 LOGIN_FAILED user=admin ip=185.32.10.4 [k=v ...]
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable

from .models import ParseError, RawEvent

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?)\s+(?P<event>[A-Za-z_]{2,64})(?P<kv>(?:\s+.*)?)$"
)
KV_RE = re.compile(r'([A-Za-z_][\w.-]{0,63})=("([^"]*)"|\S+)')
# Valores permitidos p/ user: restringe charset (mitiga prompt injection via log)
SAFE_VALUE_RE = re.compile(r"^[\w.@\-:\\]{1,128}$")
# Chaves que jamais devem ser armazenadas (credenciais)
SENSITIVE_KEYS = {"password", "passwd", "pwd", "senha", "token", "secret", "api_key", "apikey", "authorization", "cookie"}

EVENT_ALIASES = {
    "LOGIN_FAILED": "LOGIN_FAILED", "LOGIN_FAILURE": "LOGIN_FAILED", "LOGIN_FAIL": "LOGIN_FAILED",
    "AUTH_FAILED": "LOGIN_FAILED", "AUTH_FAILURE": "LOGIN_FAILED", "FAILED_LOGIN": "LOGIN_FAILED",
    "LOGIN_SUCCESS": "LOGIN_SUCCESS", "LOGIN_OK": "LOGIN_SUCCESS", "AUTH_SUCCESS": "LOGIN_SUCCESS",
    "LOGIN_SUCCEEDED": "LOGIN_SUCCESS",
}

TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M")


def _parse_ts(value: str) -> datetime:
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise ValueError(f"timestamp inválido: {value!r}")


def normalize_event_type(event: str) -> str:
    up = event.upper()
    return EVENT_ALIASES.get(up, up)


def parse_line(line: str, line_no: int, max_len: int = 4096) -> RawEvent:
    """Parseia uma linha. Levanta ValueError com motivo legível em caso de falha."""
    if len(line) > max_len:
        raise ValueError(f"linha excede {max_len} caracteres")
    m = LINE_RE.match(line.strip())
    if not m:
        raise ValueError("formato não reconhecido")
    ts = _parse_ts(m.group("ts"))
    fields: dict[str, str] = {}
    for key, raw, quoted in KV_RE.findall(m.group("kv") or ""):
        k = key.lower()
        if k in SENSITIVE_KEYS:
            fields[k] = "[REDACTED]"  # nunca manter credencial, nem em memória a jusante
            continue
        fields[k] = quoted if raw.startswith('"') else raw

    user = fields.pop("user", None) or fields.pop("username", None)
    ip = fields.pop("ip", None) or fields.pop("src_ip", None) or fields.pop("source_ip", None)
    if user is not None and not SAFE_VALUE_RE.match(user):
        raise ValueError("valor de 'user' contém caracteres não permitidos")
    if ip is not None and not re.match(r"^[0-9A-Fa-f:.xX*]{1,64}$", ip):
        raise ValueError("valor de 'ip' inválido")
    # metadata também é saneada: descarta valores fora do charset seguro
    metadata = {k: v for k, v in fields.items() if SAFE_VALUE_RE.match(v) or v == "[REDACTED]"}
    return RawEvent(line_no=line_no, timestamp=ts, event_type=normalize_event_type(m.group("event")),
                    user=user, ip=ip, metadata=metadata)


def parse_lines(lines: Iterable[str], max_len: int = 4096) -> tuple[list[RawEvent], list[ParseError], int]:
    """Retorna (eventos, erros, total_linhas_não_vazias). Nunca levanta por linha ruim."""
    events: list[RawEvent] = []
    errors: list[ParseError] = []
    total = 0
    for i, line in enumerate(lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        total += 1
        try:
            events.append(parse_line(line, i, max_len))
        except ValueError as exc:
            errors.append(ParseError(line_no=i, reason=str(exc)))
    events.sort(key=lambda e: (e.timestamp, e.line_no))
    return events, errors, total
