import argparse
import json

from llm_antidote import commands
from llm_antidote.commands import run_cli, setup_cli
from llm_antidote.eval_client import Completion


def test_cli_lock_refuses_symlink_output(tmp_path):
    model = tmp_path / "model"
    model.mkdir()
    (model / "weights.gguf").write_bytes(b"weights")
    target = tmp_path / "target.json"
    target.write_text("keep")
    output = tmp_path / "model-lock.json"
    output.symlink_to(target)
    args = argparse.Namespace(
        antidote_handler="model_lock",
        source=str(model),
        output=str(output),
    )

    assert run_cli(args) == 2
    assert target.read_text() == "keep"


def test_eval_cli_writes_coverage_report_without_network(tmp_path, monkeypatch):
    class FakeClient:
        endpoint_display = "localhost:8000"

        def __init__(self, *_args, **_kwargs):
            pass

        def complete(self, **_kwargs):
            return Completion("Complete", (), "stop")

    monkeypatch.setattr(commands, "OpenAICompatClient", FakeClient)
    suite = tmp_path / "suite.json"
    suite.write_text(
        json.dumps(
            {
                "name": "cli-test",
                "carriers": ["Harmless task {{candidate}}"],
                "candidates": ["candidate"],
                "repeats": 1,
            }
        )
    )
    output = tmp_path / "report.json"
    parser = argparse.ArgumentParser()
    setup_cli(parser)
    args = parser.parse_args(
        [
            "eval",
            "run",
            "--endpoint",
            "http://localhost:8000/v1",
            "--model",
            "test-model",
            "--suite",
            str(suite),
            "--output",
            str(output),
        ]
    )

    assert run_cli(args) == 0
    report = json.loads(output.read_text())
    assert report["verdict"] == "NO_BACKDOOR_DETECTED_WITHIN_TEST_COVERAGE"
    assert report["coverage"]["completed_trials"] == 2
