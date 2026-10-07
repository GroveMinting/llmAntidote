import json

import pytest

from llm_antidote.eval_suite import DEFAULT_SUITE, load_suite, suite_from_dict, with_overrides


def test_default_suite_is_bounded_and_reproducible():
    assert len(DEFAULT_SUITE.carriers) == 3
    assert DEFAULT_SUITE.repeats == 2
    assert len(DEFAULT_SUITE.digest) == 64
    assert DEFAULT_SUITE.digest == DEFAULT_SUITE.digest


def test_load_custom_suite_and_override(tmp_path):
    path = tmp_path / "suite.json"
    path.write_text(
        json.dumps(
            {
                "name": "small",
                "carriers": [{"id": "one", "prompt": "Harmless task {{candidate}}"}],
                "candidates": ["alpha", "beta"],
                "repeats": 1,
            }
        )
    )
    suite = load_suite(path)
    assert suite.min_carriers == 1
    overridden = with_overrides(suite, candidates=["custom"], repeats=2)
    assert overridden.candidates == ("custom",)
    assert overridden.repeats == 2


def test_suite_rejects_invalid_thresholds():
    with pytest.raises(ValueError, match="activation_threshold"):
        suite_from_dict(
            {
                "carriers": ["task"],
                "candidates": ["candidate"],
                "activation_threshold": 2,
            }
        )

    with pytest.raises(ValueError, match="max_error_rate"):
        suite_from_dict(
            {
                "carriers": ["task"],
                "candidates": ["candidate"],
                "max_error_rate": 1.0,
            }
        )


def test_suite_rejects_non_json(tmp_path):
    path = tmp_path / "suite.yaml"
    path.write_text("name: not-json\n")
    with pytest.raises(ValueError, match="valid JSON"):
        load_suite(path)


def test_suite_converts_deep_json_recursion_to_value_error(tmp_path):
    path = tmp_path / "deep.json"
    path.write_text("[" * 10_000 + "0" + "]" * 10_000)
    with pytest.raises(ValueError, match="valid JSON"):
        load_suite(path)


def test_suite_caps_worst_case_request_budget():
    with pytest.raises(ValueError, match="requests"):
        suite_from_dict(
            {
                "carriers": [f"task-{index}" for index in range(100)],
                "candidates": ["candidate"],
                "repeats": 8,
                "max_steps": 8,
            }
        )
