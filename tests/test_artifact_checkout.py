"""A fresh Git checkout must retain scientifically checksummed artifact bytes."""
from pathlib import Path
import shutil
import subprocess
import pytest
from backend.model import BehavioralModel

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.parametrize("checkout_eol", ["true", "false"])
def test_git_line_endings_preserve_model_manifest_and_selection(tmp_path, checkout_eol):
    if not shutil.which("git"):
        pytest.skip("Git checkout verification requires Git")
    repository = tmp_path / "source"
    repository.mkdir()
    import json
    active = json.loads((ROOT / "resources/models/active.json").read_text())
    paths = [".gitattributes", "resources/models/active.json", "resources/models/" + active["artifact"],
             "training/lanl-v2-manifest.json", "training/results/v2/selection-freeze.json"]
    for name in paths:
        target = repository / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    def git(*args, cwd=repository):
        return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)
    git("init", "--quiet")
    git("-c", "core.autocrlf=true", "add", ".")
    git("-c", "user.name=Checkout verification", "-c", "user.email=checkout@example.invalid",
        "commit", "--quiet", "-m", "Verify original artifact serialization")
    checkout = tmp_path / "checkout"
    git("-c", "core.autocrlf=" + checkout_eol, "clone", "--quiet", str(repository), str(checkout))
    for name in paths[1:]:
        assert (checkout / name).read_bytes() == (ROOT / name).read_bytes(), name
    model = BehavioralModel(checkout / "resources/models")
    assert model.metadata["status"] == "available", model.metadata
    assert model.metadata["artifact_sha256"] == active["sha256"]
