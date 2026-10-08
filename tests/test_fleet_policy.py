import copy

import pytest

from llm_antidote.fleet_policy import default_policy, policy_digest, validate_policy


def test_default_policy_is_valid_and_digest_is_stable():
    policy = default_policy("production")
    assert validate_policy(policy) is policy
    assert len(policy_digest(policy)) == 64
    assert policy_digest(policy) == policy_digest(copy.deepcopy(policy))


def test_policy_rejects_control_names_bad_time_and_non_finite_rate():
    policy = default_policy()
    policy["name"] = "production\nforged"
    with pytest.raises(ValueError, match="Policy name"):
        validate_policy(policy)

    policy = default_policy()
    policy["issued_at"] = "not-a-time"
    with pytest.raises(ValueError, match="ISO-8601"):
        validate_policy(policy)

    policy = default_policy()
    policy["admission"]["max_error_rate"] = float("nan")
    with pytest.raises(ValueError, match="max_error_rate"):
        validate_policy(policy)
