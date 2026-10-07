import pytest

from llm_antidote.model_lock import create_lock, load_lock, verify_lock, write_lock


def test_lock_round_trip_and_change_detection(tmp_path):
    model = tmp_path / "model"
    model.mkdir()
    (model / "config.json").write_text("{}")
    (model / "model.safetensors").write_bytes(b"weights")
    lock = create_lock(model)
    lock_path = write_lock(lock, tmp_path / "model-lock.json")

    assert verify_lock(load_lock(lock_path))["ok"]

    (model / "model.safetensors").write_bytes(b"tampered")
    result = verify_lock(load_lock(lock_path))
    assert not result["ok"]
    assert result["changed"] == ["model.safetensors"]


def test_lock_detects_missing_and_unexpected_files(tmp_path):
    model = tmp_path / "model"
    model.mkdir()
    original = model / "config.json"
    original.write_text("{}")
    lock = create_lock(model)
    original.unlink()
    (model / "extra.txt").write_text("extra")

    result = verify_lock(lock)
    assert result["missing"] == ["config.json"]
    assert result["unexpected"] == ["extra.txt"]


def test_lock_can_exclude_output_inside_model_directory(tmp_path):
    model = tmp_path / "model"
    model.mkdir()
    (model / "weights.gguf").write_bytes(b"weights")
    (model / "model-lock.json").write_text("old")
    lock = create_lock(model, exclude=("model-lock.json",))
    assert [item["path"] for item in lock["files"]] == ["weights.gguf"]


def test_lock_refuses_model_symlinks(tmp_path):
    model = tmp_path / "model"
    model.mkdir()
    outside = tmp_path / "outside.gguf"
    outside.write_bytes(b"outside")
    (model / "weights.gguf").symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        create_lock(model)


def test_verify_detects_file_replaced_by_symlink(tmp_path):
    model = tmp_path / "model"
    model.mkdir()
    weight = model / "weights.gguf"
    weight.write_bytes(b"weights")
    lock = create_lock(model)
    weight.unlink()
    outside = tmp_path / "outside.gguf"
    outside.write_bytes(b"weights")
    weight.symlink_to(outside)
    result = verify_lock(lock)
    assert not result["ok"]
    assert result["changed"] == ["weights.gguf"]


def test_write_lock_refuses_symlink_output(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("keep")
    output = tmp_path / "model-lock.json"
    output.symlink_to(target)
    with pytest.raises(ValueError, match="symlinked lockfile"):
        write_lock({"schema": "test"}, output)
    assert target.read_text() == "keep"
