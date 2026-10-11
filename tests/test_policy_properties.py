import pytest

pytest.importorskip("hypothesis")

from hypothesis import given, settings
from hypothesis import strategies as st

from llm_antidote.capabilities import classify_tool
from llm_antidote.policy import (
    PolicyConfig,
    PolicyEngine,
    _argument_text,
    extract_read_paths,
    sensitive_categories,
)

_JSONISH = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=500),
    lambda children: st.lists(children, max_size=8)
    | st.dictionaries(st.text(max_size=50), children, max_size=8),
    max_leaves=40,
)


@settings(max_examples=200, deadline=None)
@given(st.text(max_size=100))
def test_classify_tool_is_total_and_consistent(name):
    profile = classify_tool(name)
    assert profile.name == name.lower().strip()
    if profile.read_only:
        assert not profile.outbound
        assert not profile.executes
        assert not profile.persists


@settings(max_examples=200, deadline=None)
@given(st.text(max_size=2000))
def test_sensitive_categories_is_total(text):
    assert isinstance(sensitive_categories(text), tuple)


@settings(max_examples=200, deadline=None)
@given(_JSONISH)
def test_extract_read_paths_is_total(value):
    paths = extract_read_paths(value)
    assert all(isinstance(item, str) for item in paths)


@settings(max_examples=200, deadline=None)
@given(
    st.text(max_size=100),
    _JSONISH,
    st.sampled_from(["balanced", "strict", "audit"]),
)
def test_assess_is_total(name, args, mode):
    decision = PolicyEngine(PolicyConfig.from_value(mode)).assess(name, args)
    assert decision.action in {"allow", "approve", "block"}
    assert decision.would_action in {"allow", "approve", "block"}


@settings(max_examples=200, deadline=None)
@given(_JSONISH, st.integers(min_value=4096, max_value=20_000))
def test_argument_text_respects_scan_limit(value, limit):
    text, oversized = _argument_text(value, limit)
    assert len(text) <= limit
    if not oversized:
        assert len(text) <= limit
