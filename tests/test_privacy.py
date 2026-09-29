from datetime import datetime

from log_analyzer.models import RawEvent
from log_analyzer.privacy import anonymize, classify_ip, is_off_hours, is_suspicious, mask_ip


def test_mask_ip():
    assert mask_ip("185.32.10.4") == "185.32.x.x"
    assert mask_ip("185.32.x.x") == "185.32.x.x"
    assert mask_ip("2001:db8::1") == "2001:0db8:x:x:x:x:x:x"


def test_classify_ip():
    assert classify_ip("185.32.x.x") == "external"
    assert classify_ip("8.8.8.8") == "external"
    assert classify_ip("10.1.2.3") == "internal"
    assert classify_ip("192.168.x.x") == "internal"
    assert classify_ip(None) == "unknown"


def test_suspicious_and_hours():
    assert is_suspicious("203.0.113.9", ["203.0.113.0/24"])
    assert not is_suspicious("185.32.x.x", ["203.0.113.0/24"])
    assert is_off_hours(datetime(2026, 9, 29, 3, 0), 7, 20)
    assert not is_off_hours(datetime(2026, 9, 29, 14, 0), 7, 20)


def test_anonymize_pseudonymizes_users_and_drops_raw_ip(settings):
    raw = RawEvent(line_no=1, timestamp=datetime(2026, 9, 29, 14, 0), event_type="LOGIN_FAILED",
                   user="joao.silva", ip="185.32.10.4")
    ev = anonymize(raw, settings)
    assert ev.user.startswith("user_") and "joao" not in ev.user
    assert ev.ip == "185.32.x.x" and "185.32.10.4" not in ev.model_dump_json()
    assert ev.ip_scope == "external" and ev.success is False and not ev.privileged
    # determinístico => permite correlação
    assert anonymize(raw, settings).user == ev.user


def test_privileged_account_kept_readable(settings):
    raw = RawEvent(line_no=1, timestamp=datetime(2026, 9, 29, 14, 0), event_type="LOGIN_SUCCESS", user="Admin")
    ev = anonymize(raw, settings)
    assert ev.privileged and ev.user == "Admin" and ev.success is True
