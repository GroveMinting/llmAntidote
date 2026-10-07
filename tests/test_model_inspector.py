import json
from io import BytesIO

from llm_antidote.model_inspector import HuggingFaceClient, inspect_huggingface, inspect_local


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def read(self, *_args):
        return json.dumps(self.payload).encode()


def test_local_inspection_reports_formats_and_lineage(tmp_path):
    (tmp_path / "config.json").write_text(
        json.dumps(
            {
                "model_type": "test",
                "architectures": ["TestModel"],
                "_name_or_path": "base/model",
            }
        )
    )
    (tmp_path / "model.safetensors").write_bytes(b"safe-header")
    (tmp_path / "legacy.bin").write_bytes(b"pickle-ish")
    (tmp_path / "modeling_test.py").write_text("class TestModel: pass\n")

    report = inspect_local(tmp_path, deep=True)

    assert report.metadata["base_model"] == "base/model"
    assert all(item.digest for item in report.files)
    codes = {finding.code for finding in report.findings}
    assert "format.pickle_weights" in codes
    assert "repository.executable_code" in codes


def test_local_inspection_flags_missing_metadata(tmp_path):
    (tmp_path / "model.gguf").write_bytes(b"GGUF")
    report = inspect_local(tmp_path)
    assert "metadata.missing_lineage" in {finding.code for finding in report.findings}


def test_huggingface_inspection_resolves_revision_and_lfs_digest():
    sha = "a" * 40
    payload = {
        "sha": sha,
        "author": "publisher",
        "siblings": [
            {"rfilename": "config.json", "blobId": "b" * 40, "size": 10},
            {"rfilename": "model.safetensors", "lfs": {"oid": "c" * 64, "size": 100}},
        ],
        "cardData": {"base_model": "base/model"},
    }
    requested_urls = []

    def opener(request, timeout):
        requested_urls.append(request.full_url)
        assert timeout == 20
        return FakeResponse(payload)

    client = HuggingFaceClient(opener=opener)
    report = inspect_huggingface("hf:publisher/model", revision=sha, client=client)

    assert report.resolved_revision == sha
    assert report.metadata["base_model"] == "base/model"
    assert report.files[1].digest == "c" * 64
    assert not any(f.code == "revision.mutable_reference" for f in report.findings)
    assert requested_urls[0].endswith(f"/publisher/model/revision/{sha}")


def test_huggingface_mutable_revision_is_reported():
    payload = {"sha": "a" * 40, "siblings": [], "cardData": {}}
    client = HuggingFaceClient(opener=lambda *_args, **_kwargs: FakeResponse(payload))
    report = inspect_huggingface("publisher/model", revision="main", client=client)
    codes = {finding.code for finding in report.findings}
    assert "revision.mutable_reference" in codes
    assert "metadata.missing_lineage" in codes


def test_huggingface_immutable_revision_mismatch_is_high_severity():
    payload = {"sha": "b" * 40, "siblings": [], "cardData": {"base_model": "base/model"}}
    client = HuggingFaceClient(opener=lambda *_args, **_kwargs: FakeResponse(payload))
    report = inspect_huggingface("publisher/model", revision="a" * 40, client=client)
    finding = next(f for f in report.findings if f.code == "revision.mismatch")
    assert finding.severity == "high"


def test_local_inspection_does_not_follow_metadata_symlink(tmp_path):
    external = tmp_path.parent / "external-config.json"
    external.write_text(json.dumps({"_name_or_path": "private/lineage"}))
    (tmp_path / "config.json").symlink_to(external)
    (tmp_path / "model.safetensors").write_bytes(b"weights")

    report = inspect_local(tmp_path)

    assert report.metadata["base_model"] == ""
    assert "filesystem.symlink" in {finding.code for finding in report.findings}


def test_sha_stream_works_with_file_like_object():
    from llm_antidote.model_inspector import sha256_stream

    assert sha256_stream(BytesIO(b"abc")) == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
