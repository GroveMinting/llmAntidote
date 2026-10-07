from llm_antidote.audit import MetadataAudit
from llm_antidote.state import SessionRiskStore


def test_session_taint_expires():
    now = [0.0]
    store = SessionRiskStore(ttl_minutes=1, clock=lambda: now[0])
    store.mark("session-a", ("environment_secret",))
    assert store.is_tainted("session-a")
    now[0] = 61.0
    assert not store.is_tainted("session-a")


def test_session_taint_is_isolated_and_clearable():
    store = SessionRiskStore()
    store.mark("session-a", ("credential_file",))
    assert store.is_tainted("session-a")
    assert not store.is_tainted("session-b")
    store.clear("session-a")
    assert not store.is_tainted("session-a")


def test_audit_events_contain_no_arguments_or_results():
    secret = "sk_live_SUPERSECRET123"
    audit = MetadataAudit(capacity=20)
    audit.record(
        action="block",
        would_action="block",
        tool_name=secret,
        rule_ids=("exfil.environment_secret",),
        session_key="real-session-id",
    )
    serialized = repr(audit.events())
    assert secret not in serialized
    assert "real-session-id" not in serialized
    assert "session_ref" in serialized
    assert "tool_ref" in serialized
    assert "plugin_or_unknown" in serialized
    assert audit.summary()["counts"] == {"block": 1}
