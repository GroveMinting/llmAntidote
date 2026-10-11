from llm_antidote.audit import MetadataAudit
from llm_antidote.state import SessionRiskStore


def test_session_taint_expires():
    now = [0.0]
    store = SessionRiskStore(ttl_minutes=1, clock=lambda: now[0])
    store.mark("session-a", ("environment_secret",))
    assert store.is_tainted("session-a")
    now[0] = 61.0
    assert not store.is_tainted("session-a")


def test_pending_reservation_lifecycle():
    store = SessionRiskStore()
    assert not store.has_pending("session-a")
    store.reserve_pending(("session-a",))
    assert store.has_pending("session-a")
    store.release_pending(("session-a",))
    assert not store.has_pending("session-a")


def test_concurrent_pending_reservations_are_counted():
    store = SessionRiskStore()
    store.reserve_pending(("session-a",))
    store.reserve_pending(("session-a",))
    store.release_pending(("session-a",))
    assert store.has_pending("session-a")
    store.release_pending(("session-a",))
    assert not store.has_pending("session-a")


def test_pending_expires_with_ttl():
    now = [0.0]
    store = SessionRiskStore(ttl_minutes=1, clock=lambda: now[0])
    store.reserve_pending(("session-a",))
    assert store.has_pending("session-a")
    now[0] = 61.0
    assert not store.has_pending("session-a")


def test_pending_and_taint_share_session_aliases():
    store = SessionRiskStore()
    store.reserve_pending(("session-a", "task-a"))
    assert store.has_pending("task-a")
    store.mark_many(("session-a", "task-a"), ("read_outside_safe_root",))
    store.release_pending(("session-a",))
    assert not store.has_pending("task-a")
    assert store.is_tainted("task-a")


def test_clear_removes_pending_state():
    store = SessionRiskStore()
    store.reserve_pending(("session-a",))
    store.clear("session-a")
    assert not store.has_pending("session-a")



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
