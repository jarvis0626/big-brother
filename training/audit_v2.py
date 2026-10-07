"""Describe frozen v2 failures without training, new thresholds or selection."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import time
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.model import TOKENS, CONTEXT, gru_predict, baseline_predict
from training.provenance import sha256

def main():
    out = ROOT / "training/results/v2"
    cache = ROOT / "training/cache/v2"
    frozen = json.loads((out / "selection-freeze.json").read_text())
    metrics = json.loads((out / "metrics.json").read_text())
    if sha256(out / "selection-freeze.json") != metrics["selection_freeze_sha256"]:
        raise ValueError("Selection freeze changed after testing")
    for name, expected in frozen["candidate_artifacts"].items():
        if sha256(out / "models" / f"{name}.json") != expected:
            raise ValueError("Frozen model changed: " + name)
    windows = np.load(cache / "windows.npz", allow_pickle=False)
    targets = windows["test"][:, CONTEXT:].ravel()
    training_targets = windows["train"][:, CONTEXT:].ravel()
    selected = np.load(cache / f"{metrics['selected_neural']}-fresh-test.npz", allow_pickle=False)["nll"]
    baseline = np.load(cache / f"{metrics['selected_baseline']}-fresh-test.npz", allow_pickle=False)["nll"]
    groups = []
    for token, name in enumerate(TOKENS):
        mask = targets == token
        count = int(mask.sum())
        groups.append({"token": name, "test_targets": count, "training_targets": int((training_targets == token).sum()),
            "temporal_next_event_nll_nats": float(selected[mask].mean()) if count else None,
            "baseline_next_event_nll_nats": float(baseline[mask].mean()) if count else None})
    inference = {}
    for name in frozen["candidate_artifacts"]:
        weights = json.loads((out / "models" / f"{name}.json").read_text())
        predict = gru_predict if weights["architecture"] == "gru" else baseline_predict
        measurements = []
        for window in windows["test"][:30]:
            stamp = time.perf_counter()
            predict(weights, window[:CONTEXT].tolist())
            measurements.append((time.perf_counter() - stamp) * 1000)
        inference[name] = {"median_ms": float(np.median(measurements)), "p95_ms": float(np.quantile(measurements, .95)),
            "samples": len(measurements), "scope": "One16-token prediction using actual exported standard-library runtime; no Electron, no collection, not full8-target session score"}
    result = {"selection_freeze_sha256": metrics["selection_freeze_sha256"],
        "purpose": "Frozen descriptive per-token failure analysis. No fitting, thresholds or candidate selection changed.",
        "per_token": groups,
        "seed_capacity_results": [{"id": candidate["id"],
            "validation_nll_nats": candidate["validation"]["next_event_nll_nats"],
            "fresh_test_nll_nats": candidate["test"]["next_event_nll_nats"]} for candidate in metrics["candidate_results"]],
        "inference_standard_library": inference,
        "interpretation": "Conditional surprise is prediction loss. Rare token groups have unstable estimates; absent types cannot be evaluated. No malware labels or confidence intervals implied."}
    (out / "frozen-audit.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf8")
    print(json.dumps(result), flush=True)

if __name__ == "__main__":
    main()
