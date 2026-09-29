"""Engenharia de features e agregação temporal.

Três visões:
- "account": sessões por (ip_ref, user)  -> força bruta clássica contra uma conta.
- "source":  sessões por ip_ref           -> password spraying (muitas contas, mesmo IP).
- "target":  sessões por user             -> força bruta distribuída (mesma conta, vários IPs).
Uma sessão é quebrada quando o intervalo entre eventos consecutivos excede `window_minutes`.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Hashable

from .models import NormalizedEvent

AUTH_TYPES = {"LOGIN_FAILED", "LOGIN_SUCCESS"}


@dataclass
class GroupFeatures:
    kind: str                      # "account" | "source" | "target"
    key: dict
    events: list[NormalizedEvent]
    n_failures: int = 0
    n_successes: int = 0
    distinct_users: int = 0
    distinct_ips: int = 0
    max_failure_streak: int = 0
    success_after_failures: bool = False
    failures_before_success: int = 0
    off_hours_events: int = 0
    privileged: bool = False
    ip_scope: str = "unknown"
    ip_suspicious: bool = False
    duration_seconds: float = 0.0
    failures_per_minute: float = 0.0
    evidence_lines: list[int] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if k != "events"}


def _sessionize(events: list[NormalizedEvent], window: timedelta) -> list[list[NormalizedEvent]]:
    sessions: list[list[NormalizedEvent]] = []
    for ev in events:  # eventos já ordenados por timestamp
        if sessions and ev.timestamp - sessions[-1][-1].timestamp <= window:
            sessions[-1].append(ev)
        else:
            sessions.append([ev])
    return sessions


def compute(kind: str, key: dict, evs: list[NormalizedEvent], failure_threshold: int) -> GroupFeatures:
    f = GroupFeatures(kind=kind, key=key, events=evs)
    streak = 0
    for ev in evs:
        if ev.success is False:
            f.n_failures += 1
            streak += 1
            f.max_failure_streak = max(f.max_failure_streak, streak)
        elif ev.success is True:
            f.n_successes += 1
            if streak >= failure_threshold and not f.success_after_failures:
                f.success_after_failures = True
                f.failures_before_success = streak
            streak = 0
        f.off_hours_events += int(ev.off_hours)
        f.privileged |= ev.privileged
        f.ip_suspicious |= ev.ip_suspicious
    f.distinct_users = len({e.user for e in evs if e.user})
    f.distinct_ips = len({e.ip_ref for e in evs if e.ip_ref})
    scopes = {e.ip_scope for e in evs}
    f.ip_scope = "external" if "external" in scopes else ("internal" if "internal" in scopes else "unknown")
    f.duration_seconds = (evs[-1].timestamp - evs[0].timestamp).total_seconds()
    f.failures_per_minute = round(f.n_failures / max(f.duration_seconds / 60, 1.0), 2)
    f.evidence_lines = [e.line_no for e in evs]
    return f


def build_groups(events: list[NormalizedEvent], window_minutes: int, failure_threshold: int) -> list[GroupFeatures]:
    window = timedelta(minutes=window_minutes)
    auth = [e for e in events if e.event_type in AUTH_TYPES]

    by_account: dict[Hashable, list[NormalizedEvent]] = defaultdict(list)
    by_source: dict[Hashable, list[NormalizedEvent]] = defaultdict(list)
    by_target: dict[Hashable, list[NormalizedEvent]] = defaultdict(list)
    for e in auth:
        by_account[(e.ip_ref, e.user)].append(e)
        by_source[e.ip_ref].append(e)
        by_target[e.user].append(e)

    groups: list[GroupFeatures] = []
    for (ip_ref, user), evs in by_account.items():
        for sess in _sessionize(evs, window):
            groups.append(compute("account", {"user": user, "ip": sess[0].ip}, sess, failure_threshold))
    for ip_ref, evs in by_source.items():
        for sess in _sessionize(evs, window):
            if len({e.user for e in sess}) > 1:  # só interessa se houver várias contas
                groups.append(compute("source", {"ip": sess[0].ip}, sess, failure_threshold))
    for user, evs in by_target.items():
        for sess in _sessionize(evs, window):
            if len({e.ip_ref for e in sess}) > 1:  # só interessa se houver vários IPs
                groups.append(compute("target", {"user": user}, sess, failure_threshold))
    return groups
