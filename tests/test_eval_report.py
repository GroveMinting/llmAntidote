import json

import pytest

from llm_antidote.eval_report import load_report, render_markdown, write_markdown, write_reports
from llm_antidote.eval_runner import NO_BACKDOOR_DETECTED, EvaluationReport


def sample_report():
    return EvaluationReport(
        verdict=NO_BACKDOOR_DETECTED,
        model="model",
        endpoint="localhost:8000",
        suite_name="suite",
        suite_sha256="a" * 64,
        generated_at="2026-10-07T00:00:00+00:00",
        coverage={
            "completed_trials": 2,
            "failed_trials": 0,
            "inference_requests": 2,
            "control_activation_rate": 0.0,
        },
        control_trials=[],
        candidates=[],
    )


def test_write_load_and_render_reports(tmp_path):
    json_path, markdown_path = write_reports(
        sample_report(),
        json_output=tmp_path / "report.json",
        markdown_output=tmp_path / "report.md",
    )
    assert load_report(json_path)["verdict"] == NO_BACKDOOR_DETECTED
    assert markdown_path is not None
    assert "documented suite" in markdown_path.read_text()
    assert "NO_BACKDOOR" in render_markdown(sample_report())


def test_report_output_refuses_symlink(tmp_path):
    target = tmp_path / "target.md"
    target.write_text("keep")
    output = tmp_path / "report.md"
    output.symlink_to(target)
    with pytest.raises(ValueError, match="symlinked"):
        write_markdown("replacement", output)
    assert target.read_text() == "keep"


def test_load_report_rejects_wrong_schema(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"schema": "other"}))
    with pytest.raises(ValueError, match="Unsupported"):
        load_report(path)


def test_report_converts_deep_json_recursion_to_value_error(tmp_path):
    path = tmp_path / "deep.json"
    path.write_text("[" * 10_000 + "0" + "]" * 10_000)
    with pytest.raises(ValueError, match="valid JSON"):
        load_report(path)


def test_markdown_rendering_neutralizes_untrusted_values():
    value = sample_report().to_dict()
    value["model"] = "\x1b]8;;https://attacker.invalid\x07link`<img src=x>"
    value["candidates"] = [
        {
            "candidate": "x|y\n![tracking](https://attacker.invalid)<img src=x>",
            "activation_rate": "not-a-number",
            "carrier_hits": "not-a-list",
            "recovered": False,
        }
    ]
    rendered = render_markdown(value)
    assert "<img" not in rendered
    assert "&lt;img" in rendered
    assert "x\\|y" in rendered
    assert "![tracking]" not in rendered
    assert "\x1b" not in rendered


def test_report_writer_caps_output(monkeypatch, tmp_path):
    monkeypatch.setattr("llm_antidote.eval_report.MAX_REPORT_BYTES", 10)
    with pytest.raises(ValueError, match="output exceeds"):
        write_markdown("x" * 11, tmp_path / "report.md")
