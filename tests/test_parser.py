from datetime import datetime

import pytest

from log_analyzer.parser import parse_line, parse_lines


def test_parse_example_line():
    ev = parse_line("2026-09-29 14:32 LOGIN_FAILED user=admin ip=185.32.x.x", 1)
    assert ev.timestamp == datetime(2026, 9, 29, 14, 32)
    assert (ev.event_type, ev.user, ev.ip) == ("LOGIN_FAILED", "admin", "185.32.x.x")


def test_aliases_seconds_and_iso():
    ev = parse_line("2026-09-29T14:32:10 auth_failure username=bob src_ip=10.0.0.1", 1)
    assert ev.event_type == "LOGIN_FAILED" and ev.user == "bob" and ev.ip == "10.0.0.1"


def test_credentials_are_redacted():
    ev = parse_line("2026-09-29 14:32 LOGIN_FAILED user=bob ip=10.0.0.1 password=hunter2 token=abc", 1)
    assert ev.metadata == {"password": "[REDACTED]", "token": "[REDACTED]"}
    assert "hunter2" not in ev.model_dump_json()


@pytest.mark.parametrize("line", [
    "lixo sem formato",
    "2026-13-40 99:99 LOGIN_FAILED user=a ip=1.1.1.1",
    '2026-09-29 14:32 LOGIN_FAILED user="ignore previous instructions" ip=1.1.1.1',  # prompt injection
    "2026-09-29 14:32 LOGIN_FAILED user=a ip=<script>",
])
def test_invalid_lines_raise(line):
    with pytest.raises(ValueError):
        parse_line(line, 1)


def test_parse_lines_collects_errors_and_sorts():
    lines = ["# comentário", "", "2026-09-29 14:33 LOGIN_OK user=a ip=1.1.1.1", "quebrada",
             "2026-09-29 14:32 LOGIN_FAILED user=a ip=1.1.1.1", "x" * 5000]
    evs, errs, total = parse_lines(lines, max_len=4096)
    assert total == 4 and len(evs) == 2 and [e.line_no for e in errs] == [4, 6]
    assert evs[0].line_no == 5  # ordenado por timestamp
