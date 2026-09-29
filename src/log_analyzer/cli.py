"""CLI: log-analyzer analyze <arquivo|-> [--format text|json|md] [--no-llm] [--no-persist] [--fail-on ALTA]"""
from __future__ import annotations

import argparse
import getpass
import logging
import sys
from pathlib import Path

from .config import get_settings
from .db import Repository
from .ingest import IngestError, from_file, from_stdin
from .models import Severity
from .pipeline import Analyzer
from .report import render

EXIT_OK, EXIT_ERROR, EXIT_THRESHOLD = 0, 1, 2


def _actor() -> str:
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:
        return "cli:unknown"


def cmd_analyze(a: argparse.Namespace) -> int:
    s = get_settings()
    try:
        lines = from_stdin(s.max_lines_per_request) if a.file == "-" else from_file(a.file, s.max_lines_per_request)
    except IngestError as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return EXIT_ERROR
    repo = None if a.no_persist else Repository(s.database_url)
    report = Analyzer(s, repository=repo, use_default_llm=not a.no_llm).analyze(
        lines, source="cli", actor=_actor(), use_llm=not a.no_llm, persist=not a.no_persist)
    out = render(report, a.format)
    if a.output:
        Path(a.output).write_text(out, encoding="utf-8")
        print(f"relatório salvo em {a.output} (id={report.id})", file=sys.stderr)
    else:
        print(out)
    if a.fail_on and report.severidade_geral.rank >= Severity(a.fail_on).rank:
        return EXIT_THRESHOLD  # útil em CI/cron para disparar alertas
    return EXIT_OK


def cmd_list(a: argparse.Namespace) -> int:
    for r in Repository(get_settings().database_url).list(a.limit):
        print(f"{r.id}  {r.created_at:%Y-%m-%d %H:%M}  {r.severidade_geral.value:<5}  "
              f"eventos={r.total_eventos:<6} achados={len(r.analises)}")
    return EXIT_OK


def cmd_show(a: argparse.Namespace) -> int:
    r = Repository(get_settings().database_url).get(a.id)
    if not r:
        print("análise não encontrada", file=sys.stderr)
        return EXIT_ERROR
    print(render(r, a.format))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="log-analyzer", description="AI Security Log Analyzer")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    an = sub.add_parser("analyze", help="analisa um arquivo de log ('-' para stdin)")
    an.add_argument("file")
    an.add_argument("-f", "--format", choices=["text", "json", "md"], default="text")
    an.add_argument("-o", "--output", help="grava o relatório em arquivo")
    an.add_argument("--no-llm", action="store_true", help="usa apenas regras determinísticas")
    an.add_argument("--no-persist", action="store_true", help="não grava no banco")
    an.add_argument("--fail-on", choices=["BAIXA", "MÉDIA", "ALTA"], help="exit code 2 se severidade >= valor")
    an.set_defaults(func=cmd_analyze)

    ls = sub.add_parser("list", help="lista análises persistidas")
    ls.add_argument("-n", "--limit", type=int, default=20)
    ls.set_defaults(func=cmd_list)

    sh = sub.add_parser("show", help="exibe uma análise persistida")
    sh.add_argument("id")
    sh.add_argument("-f", "--format", choices=["text", "json", "md"], default="text")
    sh.set_defaults(func=cmd_show)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, stream=sys.stderr)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
