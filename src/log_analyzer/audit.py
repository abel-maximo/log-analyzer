"""Trilha de auditoria da própria aplicação (JSON Lines, append-only).

Não registra conteúdo de log, credenciais ou IPs brutos, apenas metadados da operação.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

_logger: logging.Logger | None = None


def _get(path: str) -> logging.Logger:
    global _logger
    if _logger is None:
        _logger = logging.getLogger("log_analyzer.audit")
        _logger.setLevel(logging.INFO)
        _logger.propagate = False
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        h = RotatingFileHandler(path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(message)s"))
        _logger.addHandler(h)
    return _logger


def audit(path: str, action: str, actor: str, outcome: str = "success", **details) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "actor": actor,
        "outcome": outcome,
        **details,
    }
    try:
        _get(path).info(json.dumps(record, ensure_ascii=False, default=str))
    except OSError:
        logging.getLogger(__name__).error("falha ao gravar auditoria: %s", action)


def reset_for_tests() -> None:
    global _logger
    if _logger:
        for h in list(_logger.handlers):
            h.close()
            _logger.removeHandler(h)
    _logger = None
