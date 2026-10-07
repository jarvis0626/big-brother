"""Frozen v1/v2 prediction comparison on inert public Windows recordings.

No downloaded commands run. OTRF metadata identifies adversary-emulation
scenarios containing background events; this script cannot calculate malware
precision/recall. Recordings never influence epoch/threshold selection.
"""
from __future__ import annotations
import collections
import json
from pathlib import Path
import sys
import time
import numpy as np
import torch
from torch import nn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.model import CONTEXT, TARGETS, TOKENS, BehavioralModel, event_token
from training.train import contexts, neural_nll, baseline_nll, metrics
from training.datasets_v2 import iter_scenarios
from training.provenance import sha256

def windows_for(events):
    """Whole-host aggregation matches LANL; session-domain mismatch stays clear."""
    hosts = collections.defaultdict(list)
    supported, ignored = collections.Counter(), collections.Counter()
    for event in events:
        token = event_token(event)
        if token is None:
            ignored[event["kind"]] += 1
            continue
        supported[event["kind"]] += 1
        host = str((event.get("details") or {}).get("host", "unknown"))
        hosts[host].append((event["timestamp"], event.get("source_record_id", ""), token))
    windows = []
    for events in hosts.values():
        events.sort()
        tokens = [event[2] for event in events]
        for start in range(0, len(tokens) - CONTEXT - TARGETS + 1, CONTEXT + TARGETS):
            windows.append(tokens[start:start + CONTEXT + TARGETS])
    return np.asarray(windows, dtype=np.int64).reshape(-1, CONTEXT + TARGETS), supported, ignored

def torch_model(weights):
    class Predictor(nn.Module):
        def __init__(self):
            super().__init__()
            self.embedding = nn.Embedding(len(TOKENS), weights["embedding_size"])
            self.gru = nn.GRU(weights["embedding_size"], weights["hidden_size"], batch_first=True)
            self.output = nn.Linear(weights["hidden_size"], len(TOKENS))
        def forward(self, x):
            _, hidden = self.gru(self.embedding(x))
            return self.output(hidden[-1])
    names = {"embedding": "embedding.weight", "weight_ih": "gru.weight_ih_l0", "weight_hh": "gru.weight_hh_l0",
        "bias_ih": "gru.bias_ih_l0", "bias_hh": "gru.bias_hh_l0", "output_weight": "output.weight", "output_bias": "output.bias"}
    model = Predictor()
    model.load_state_dict({key: torch.tensor(weights[name], dtype=torch.float32) for name, key in names.items()})
    return model

def main():
    torch.set_num_threads(2)
    started = time.perf_counter()
    out = ROOT / "training/results/v2"
    frozen = json.loads((out / "metrics.json").read_text())
    if sha256(out / "selection-freeze.json") != frozen["selection_freeze_sha256"]:
        raise ValueError("Selection changed after the fresh test")
    models = {"unchanged_v1": BehavioralModel(out / "v1-original"),
        "selected_v2": BehavioralModel(out / "models")}
    for name, model in models.items():
        if model.metadata["status"] != "available":
            raise ValueError("Frozen model unavailable: " + name)
    networks = {name: torch_model(model.weights) if model.weights["architecture"] == "gru" else None
                for name, model in models.items()}
    summaries = {name: {"sum_nll": 0.0, "predictions": 0, "windows": 0, "exceedances": 0} for name in models}
    rows, kind_counts, ignored_counts = [], collections.Counter(), collections.Counter()
    labels = collections.Counter()
    for scenario in iter_scenarios():
        windows, supported, ignored = windows_for(scenario["events"])
        kind_counts.update(supported)
        ignored_counts.update(ignored)
        labels[scenario["provenance"]["dataset"]] += 1
        row = {"name": scenario["name"], "source_sha256": scenario["provenance"]["sha256"],
            "dataset": scenario["provenance"]["dataset"], "raw_archive_path": scenario["provenance"]["raw_archive_path"],
            "supported_events": sum(supported.values()), "ignored_events": sum(ignored.values()),
            "complete_disjoint_24_event_windows": len(windows), "models": {}}
        if len(windows):
            x, y = contexts(windows)
            for name, model in models.items():
                nll = (neural_nll(networks[name], x, y) if networks[name] is not None else baseline_nll(model.weights, x, y))
                result, scores = metrics(nll, windows, model.metadata["threshold"])
                row["models"][name] = result
                summary = summaries[name]
                summary["sum_nll"] += float(nll.sum())
                summary["predictions"] += len(nll)
                summary["windows"] += len(windows)
                summary["exceedances"] += int((scores > model.metadata["threshold"]).sum())
        rows.append(row)
    aggregates = {}
    for name, summary in summaries.items():
        count = summary["predictions"]
        windows = summary["windows"]
        aggregates[name] = {"next_event_nll_nats": summary["sum_nll"] / count if count else None,
            "predictions": count, "windows": windows, "threshold_exceedance_windows": summary["exceedances"],
            "threshold_exceedance_fraction": summary["exceedances"] / windows if windows else None,
            "model_version": models[name].metadata["version"], "artifact_sha256": models[name].metadata["artifact_sha256"],
            "threshold": models[name].metadata["threshold"]}
    result = {"purpose": "External domain-shift evaluation of frozen next-event predictors. No training or threshold/epoch retuning.",
        "scenario_count": len(rows), "scenario_sources": dict(labels), "evaluated_complete_window_scenarios": sum(bool(row["complete_disjoint_24_event_windows"]) for row in rows),
        "supported_event_counts": dict(kind_counts), "ignored_event_counts": dict(ignored_counts), "models": aggregates, "scenarios": rows,
        "limitations": ["Recorded attack-lab scenarios contain background and lack event-level labels or matched benign controls. Exceedances are neither precision nor recall.",
            "Only process starts/ends, DNS and network-port categories enter prediction. Most detailed Sysmon evidence can be outside the model feature schema.",
            "Complete disjoint24-event windows aggregate all recorded processes per host, matching LANL rather than a watched application's narrower process tree.",
            "Short captures/final fragments lacking24supported events are excluded from prediction loss; absent observations are not evidence of safety.",
            "These recordings are laboratory external checks, not a representative independent malware benchmark."],
        "metrics_unavailable": {"precision": None, "recall": None, "f1": None, "pr_auc": None, "false_positive_rate": None},
        "normalized_index_sha256": sha256(ROOT / "training/data/v2/recordings/index.json"), "total_seconds": time.perf_counter() - started}
    (out / "external-windows.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf8")
    print(json.dumps({key: value for key, value in result.items() if key != "scenarios"}), flush=True)

if __name__ == "__main__":
    main()
