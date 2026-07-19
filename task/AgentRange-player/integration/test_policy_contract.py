from policy_contract import evaluate


CONTEXT = {"principal": {"sub": "lwang", "scope": {"tenant": "acme"}}}


def test_observe_never_blocks_but_records_would_block():
    verdict = evaluate("observe", "customer-db", "query", {"tenant": "globex"}, CONTEXT)
    assert verdict["action"] == "alert"
    assert verdict["would_block"] is True


def test_action_blocks_scope_escape_and_wildcard():
    assert evaluate("action", "customer-db", "query", {"tenant": "globex"}, CONTEXT)["action"] == "block"
    assert evaluate("action", "customer-db", "query", {"tenant": "*"}, CONTEXT)["action"] == "block"
    assert evaluate("action", "customer-db", "query", {"tenant": "acme"}, CONTEXT)["action"] == "allow"


def test_approved_threat_intel_egress_is_allowed():
    verdict = evaluate("action", "threat-intel", "lookup", {"cve": "CVE-2026-1234"}, {}, "HIGH")
    assert verdict["action"] == "allow"
    assert verdict["severity"] == "NONE"


def test_sensitive_note_sync_is_blocked():
    verdict = evaluate("action", "notes-sync", "sync_note", {"text": "contents from /app/.env"}, {})
    assert verdict["action"] == "block"
