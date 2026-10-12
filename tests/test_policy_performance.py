import re
import time

import pytest

from llm_antidote.policy import (
    _DOWNLOAD_EXECUTE,
    _NETWORK_SINK,
    _REVERSE_SHELL,
    _SENSITIVE_PATTERNS,
    _UPLOAD_SINK,
    PolicyConfig,
    PolicyEngine,
)

_ADVERSARIAL_INPUTS = {
    "semicolon_run": ";" * 150_000,
    "assignment_run": "x=1;" * 40_000,
}

_PATTERNS: tuple[re.Pattern[str], ...] = (
    tuple(pattern for _, pattern in _SENSITIVE_PATTERNS)
    + _DOWNLOAD_EXECUTE
    + _REVERSE_SHELL
    + (_NETWORK_SINK, _UPLOAD_SINK)
)


@pytest.mark.parametrize("text", _ADVERSARIAL_INPUTS.values(), ids=_ADVERSARIAL_INPUTS)
def test_single_line_patterns_scanned_within_budget(text: str) -> None:
    assert len(text) >= 100_000
    started = time.perf_counter()
    for pattern in _PATTERNS:
        pattern.search(text)
    elapsed = time.perf_counter() - started
    assert elapsed < 1.0, f"pattern scan took {elapsed:.3f}s for {len(text)} chars"


@pytest.mark.parametrize("text", _ADVERSARIAL_INPUTS.values(), ids=_ADVERSARIAL_INPUTS)
def test_single_line_assess_within_budget(text: str) -> None:
    engine = PolicyEngine(PolicyConfig())
    started = time.perf_counter()
    engine.assess("terminal", {"command": text})
    engine.assess("terminal", {"command": text}, session_tainted=False)
    elapsed = time.perf_counter() - started
    assert elapsed < 1.0, f"assess took {elapsed:.3f}s for {len(text)} chars"
