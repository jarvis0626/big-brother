"""Promotion uses real frozen artifacts in isolated temporary repositories."""
import json
from pathlib import Path
import shutil
import pytest
from backend.model import BehavioralModel
from scripts import promote_model

SOURCE = Path(__file__).resolve().parents[1]

@pytest.fixture
def promotion_workspace(tmp_path, monkeypatch):
    experiment = tmp_path / "training/results/v2"
    experiment.mkdir(parents=True)
    original = SOURCE / "training/results/v2"
    for name in ("metrics.json", "selection-freeze.json"):
        shutil.copyfile(original / name, experiment / name)
    selected = json.loads((original / "selection-freeze.json").read_text())["selected_candidate"]
    shutil.copyfile(original / f"{selected}.json", experiment / f"{selected}.json")
    shutil.copytree(original / "models", experiment / "models")
    runtime = tmp_path / "resources/models"
    shutil.copytree(original / "v1-original", runtime)
    monkeypatch.setattr(promote_model, "ROOT", tmp_path)
    return experiment, runtime

def runtime_snapshot(runtime):
    return {path.relative_to(runtime).as_posix(): path.read_bytes() for path in runtime.rglob("*") if path.is_file()}

def update_json(path, mutate):
    data = json.loads(path.read_text())
    mutate(data)
    path.write_text(json.dumps(data, indent=2), encoding="utf8")

def test_dry_run_checks_real_selected_weights_without_runtime_mutation(promotion_workspace):
    experiment, runtime = promotion_workspace
    previous = runtime_snapshot(runtime)
    result = promote_model.promote(dry_run=True)
    assert result["dry_run"] is True
    assert result["version"].startswith("lanl2015-v2-")
    assert result["previous_version"].startswith("lanl2015-v1-")
    assert runtime_snapshot(runtime) == previous
    assert not (experiment / "promotion.json").exists()

@pytest.mark.parametrize("tamper,reason", [
    ("freeze", "selection changed"),
    ("threshold", "threshold differs"),
    ("selected_weights", "weights changed"),
    ("candidate", "validation winner"),
    ("artifact_pointer", "artifact differs"),
])
def test_tampering_is_rejected_before_any_runtime_mutation(promotion_workspace, tamper, reason):
    experiment, runtime = promotion_workspace
    previous = runtime_snapshot(runtime)
    index_path = experiment / "models/active.json"
    index = json.loads(index_path.read_text())
    if tamper == "freeze":
        update_json(experiment / "selection-freeze.json", lambda data: data.update(selected_candidate="another-candidate"))
    elif tamper == "threshold":
        update_json(index_path, lambda data: data.update(threshold=data["threshold"] + 0.25))
    elif tamper == "selected_weights":
        artifact = experiment / "models" / index["artifact"]
        update_json(artifact, lambda data: data["output_bias"].__setitem__(0, data["output_bias"][0] + .01))
    elif tamper == "candidate":
        update_json(experiment / "metrics.json", lambda data: data.update(selected_candidate="baseline-seed1984"))
    elif tamper == "artifact_pointer":
        update_json(index_path, lambda data: data.update(artifact="baseline-seed1984.json"))
    with pytest.raises(ValueError, match=reason):
        promote_model.promote()
    assert runtime_snapshot(runtime) == previous
    assert not (experiment / "promotion.json").exists()

def test_successful_isolated_promotion_retains_original_artifacts(promotion_workspace):
    experiment, runtime = promotion_workspace
    original = runtime_snapshot(runtime)
    result = promote_model.promote()
    loaded = BehavioralModel(runtime)
    assert loaded.metadata["status"] == "available"
    assert loaded.metadata["version"] == result["version"]
    assert loaded.metadata["artifact_sha256"] == result["artifact_sha256"]
    assert json.loads((experiment / "promotion.json").read_text())["artifact_sha256"] == result["artifact_sha256"]
    for filename, contents in original.items():
        if filename != "active.json":
            assert (runtime / filename).read_bytes() == contents
    assert not list(runtime.glob("*.tmp"))

def test_coordinated_metrics_and_index_threshold_edits_do_not_change_frozen_candidate(promotion_workspace):
    experiment, runtime = promotion_workspace
    previous = runtime_snapshot(runtime)
    index_path = experiment / "models/active.json"
    index = json.loads(index_path.read_text())
    altered = index["threshold"] + .5
    update_json(index_path, lambda data: data.update(threshold=altered))
    def change_evaluated_threshold(data):
        selected = data["selected_candidate"]
        next(row for row in data["candidate_results"] if row["id"] == selected)["threshold"] = altered
    update_json(experiment / "metrics.json", change_evaluated_threshold)
    with pytest.raises(ValueError, match="candidate result"):
        promote_model.promote()
    assert runtime_snapshot(runtime) == previous
    assert not (experiment / "promotion.json").exists()

@pytest.mark.parametrize("value", [float("nan"), float("inf"), -.01])
def test_invalid_validation_losses_reject_before_runtime_mutation(promotion_workspace, value):
    experiment, runtime = promotion_workspace
    previous = runtime_snapshot(runtime)
    def corrupt_validation(data):
        data["candidate_results"][0]["validation"]["next_event_nll_nats"] = value
    update_json(experiment / "metrics.json", corrupt_validation)
    with pytest.raises(ValueError, match="validation"):
        promote_model.promote()
    assert runtime_snapshot(runtime) == previous
    assert not (experiment / "promotion.json").exists()
