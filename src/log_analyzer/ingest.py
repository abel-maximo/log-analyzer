"""Ingestão: arquivo, stdin ou texto (API). Aplica limites contra DoS."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator


class IngestError(ValueError):
    pass


def _limited(lines: Iterator[str], max_lines: int) -> list[str]:
    out: list[str] = []
    for i, line in enumerate(lines):
        if i >= max_lines:
            raise IngestError(f"entrada excede o limite de {max_lines} linhas")
        out.append(line.rstrip("\r\n"))
    return out


def from_text(text: str, max_lines: int) -> list[str]:
    return _limited(iter(text.splitlines()), max_lines)


def from_file(path: str | Path, max_lines: int) -> list[str]:
    p = Path(path)
    if not p.is_file():
        raise IngestError(f"arquivo não encontrado: {p}")
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        return _limited(iter(fh), max_lines)


def from_stdin(max_lines: int) -> list[str]:
    return _limited(iter(sys.stdin), max_lines)
