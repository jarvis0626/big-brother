"""Promote an already frozen behavioral experiment; never fit or retune it."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.model import BehavioralModel

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def promote(dry_run=False):
    experiment = ROOT / "training/results/v2"
    metrics = json.loads((experiment / "metrics.json").read_text())
    freeze_path = experiment / "selection-freeze.json"
    freeze = json.loads(freeze_path.read_text())
    if digest(freeze_path) != metrics["selection_freeze_sha256"]:
        raise ValueError("Frozen validation selection changed after evaluation")
    selected = freeze["selected_candidate"]
    for row in metrics["candidate_results"]:
        loss = row["validation"]["next_event_nll_nats"]
        if not isinstance(loss, (int, float)) or not math.isfinite(loss) or loss < 0:
            raise ValueError("Candidate validation loss is invalid")
    best = min(metrics["candidate_results"], key=lambda row: row["validation"]["next_event_nll_nats"])
    if selected != metrics["selected_candidate"] or selected != best["id"]:
        raise ValueError("Selected candidate does not match the frozen validation winner")
    source = experiment / "models"
    index = json.loads((source / "active.json").read_text())
    if index["threshold"] != best["threshold"]:
        raise ValueError("Active threshold differs from the frozen evaluated threshold")
    if index["artifact"] != selected + ".json":
        raise ValueError("Active artifact differs from selected candidate")
    candidate = json.loads((experiment / (selected + ".json")).read_text())
    if candidate["id"] != selected or candidate["threshold"] != best["threshold"] or candidate["validation"] != best["validation"]:
        raise ValueError("Selected candidate result differs from evaluated selection")
    if not math.isfinite(index["threshold"]) or index["threshold"] < 0:
        raise ValueError("Selected threshold is invalid")
    artifact = source / index["artifact"]
    if digest(artifact) != freeze["candidate_artifacts"][selected] or digest(artifact) != index["sha256"] or digest(artifact) != candidate["artifact_sha256"]:
        raise ValueError("Selected weights changed after freezing")
    exported = BehavioralModel(source)
    if exported.metadata["status"] != "available":
        raise ValueError("Selected model cannot load: " + str(exported.metadata))
    prediction = exported.predict([0, 3, 2, 4, 1] * 3 + [0])
    if abs(sum(prediction) - 1) > 1e-6:
        raise ValueError("Selected inference distribution is invalid")
    target = ROOT / "resources/models"
    previous = json.loads((target / "active.json").read_text())
    result = {"selected_candidate": selected, "version": index["version"],
              "previous_version": previous["version"], "artifact_sha256": index["sha256"],
              "selection_freeze_sha256": metrics["selection_freeze_sha256"],
              "validation_selection_verified": True, "dry_run": dry_run,
              "objective": metrics["objective"], "fresh_test": best["test"],
              "notice": "Prediction experiment; this does not establish malware detection accuracy."}
    if not dry_run:
        old_index = (target / "active.json").read_bytes()
        # Complete model first; atomic index replacement then activates it. The old
        # baseline/temporal artifacts and Git release tag remain available.
        model_temp = target / (index["artifact"] + ".tmp")
        model_temp.write_bytes(artifact.read_bytes())
        os.replace(model_temp, target / index["artifact"])
        index_temp = target / "active.json.tmp"
        index_temp.write_bytes((source / "active.json").read_bytes())
        os.replace(index_temp, target / "active.json")
        if BehavioralModel(target).metadata["status"] != "available":
            index_temp.write_bytes(old_index)
            os.replace(index_temp, target / "active.json")
            raise ValueError("Promoted artifact failed load; previous index restored")
        result["promoted_at_utc"] = datetime.now(timezone.utc).isoformat()
        (experiment / "promotion.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf8")
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    print(json.dumps(promote(args.dry_run), indent=2))
