import argparse

from llm_antidote.commands import run_cli


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
