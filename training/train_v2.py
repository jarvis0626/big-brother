"""Expanded, later-time LANL experiments; validation selection precedes new test.

Outputs stay separate from shipped models. Four real GRUs (two shapes/two seeds),
two fairly trained centroid baselines and the frozen v1 model are compared on
the same fresh test. Numeric token arrays are cached locally, not committed.
"""
from __future__ import annotations
import argparse
import collections
import hashlib
import heapq
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.model import CONTEXT, TARGETS, TOKENS, FEATURE_SCHEMA, port_token, BehavioralModel, gru_predict, baseline_predict
from training.provenance import validate_dataset_manifest, sha256

WINDOW = CONTEXT + TARGETS
SEEDS = (1984, 2026)
SHAPES = ((8, 16), (16, 32))

def host_bucket(host):
    return int(hashlib.sha256(host.encode()).hexdigest()[:8], 16) % 10

def split_for(host, stamp, start, end):
    first = start + int((end - start + 1) * .6)
    second = start + int((end - start + 1) * .8)
    bucket = host_bucket(host)
    if bucket < 6 and start <= stamp < first:
        return "train"
    if 6 <= bucket < 8 and first <= stamp < second:
        return "validation"
    if bucket >= 8 and second <= stamp <= end:
        return "test"
    return None

def parse_record(kind, line):
    fields = line.rstrip("\n").split(",")
    stamp = int(fields[0])
    if kind == "proc" and len(fields) == 5 and fields[4] in {"Start", "End"}:
        host = fields[2]
        token = 0 if fields[4] == "Start" else 1
    elif kind == "flows" and len(fields) == 9:
        host, token = fields[2], port_token(fields[5])
    elif kind == "dns" and len(fields) == 3:
        host, token = fields[1], 2
    else:
        raise ValueError("Unsupported raw LANL schema")
    if not host or len(host) > 100:
        raise ValueError("Invalid anonymized host")
    return stamp, host, token

class Reservoir:
    def __init__(self, limit, seed):
        import numpy as np
        self.limit = limit
        self.rng = np.random.default_rng(seed)
        self.seen = 0
        self.items = []

    def add(self, item):
        self.seen += 1
        if len(self.items) < self.limit:
            self.items.append(item)
        else:
            index = int(self.rng.integers(self.seen))
            if index < self.limit:
                self.items[index] = item

def prepare(data, reference, max_train, max_eval, seed=7301):
    import numpy as np
    manifest = validate_dataset_manifest(data, reference)
    start = manifest["v1_excluded_through_second"] + 1
    end = min(part["maximum_time"] for part in manifest["partitions"])
    if end - start < 3600:
        raise ValueError("Expanded data lacks a meaningful fresh later-time interval")
    stats = {"common_time_seconds": [start, end], "v1_time_exclusion": [1, start - 1],
        "time_boundaries": [start + int((end - start + 1) * fraction) for fraction in (.6, .8)],
        "records_read": {}, "records_time_excluded": {}, "duplicate_rows_excluded": {},
        "malformed_records_excluded": {}, "split_sampling_seed": seed, "splits": {}}
    seen = {kind: set() for kind in ("proc", "flows", "dns")}
    bucket_cache = {}

    def source(part):
        kind = part["kind"]
        stats["records_read"][kind] = stats["records_time_excluded"][kind] = 0
        stats["duplicate_rows_excluded"][kind] = stats["malformed_records_excluded"][kind] = 0
        previous = -1
        with (Path(data) / f"lanl-{kind}.txt").open(encoding="ascii") as handle:
            for line_number, line in enumerate(handle):
                stats["records_read"][kind] += 1
                try:
                    stamp, host, token = parse_record(kind, line)
                except (ValueError, IndexError):
                    stats["malformed_records_excluded"][kind] += 1
                    continue
                if stamp < previous:
                    raise ValueError("Source time order changed: " + kind)
                previous = stamp
                if stamp > end:
                    break
                if stamp < start:
                    stats["records_time_excluded"][kind] += 1
                    continue
                if host not in bucket_cache:
                    bucket_cache[host] = host_bucket(host)
                first, second = stats["time_boundaries"]
                bucket = bucket_cache[host]
                split = ("train" if bucket < 6 and stamp < first else
                         "validation" if 6 <= bucket < 8 and first <= stamp < second else
                         "test" if bucket >= 8 and second <= stamp <= end else None)
                if split is None:
                    continue
                fingerprint = hashlib.sha256((kind + ":" + line).encode()).digest()
                if fingerprint in seen[kind]:
                    stats["duplicate_rows_excluded"][kind] += 1
                    continue
                seen[kind].add(fingerprint)
                yield stamp, kind, line_number, host, token, fingerprint, split

    reservoirs = {split: Reservoir(max_train if split == "train" else max_eval, seed + number)
                  for number, split in enumerate(("train", "validation", "test"))}
    buffers = {split: collections.defaultdict(list) for split in reservoirs}
    hosts = {split: {} for split in reservoirs}
    for stamp, kind, line_number, host, token, fingerprint, split in heapq.merge(*(source(p) for p in manifest["partitions"])):
        host_stats = hosts[split].setdefault(host, {"minimum_time": stamp, "maximum_time": stamp, "events": 0, "windows": 0})
        host_stats["maximum_time"] = stamp
        host_stats["events"] += 1
        buffer = buffers[split][host]
        buffer.append((token, fingerprint))
        if len(buffer) == WINDOW:
            window_id = hashlib.sha256(b"".join(value[1] for value in buffer)).hexdigest()
            reservoirs[split].add(([value[0] for value in buffer], window_id))
            buffer.clear()
            host_stats["windows"] += 1
    # Host buckets guarantee separation; assert it to detect implementation drift.
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        if set(hosts[left]) & set(hosts[right]):
            raise ValueError("Host overlap across splits")
    windows = {}
    all_ids = set()
    for split, reservoir in reservoirs.items():
        if len(reservoir.items) < 100:
            raise ValueError("Too few fresh held-out windows: " + split)
        window_ids = [item[1] for item in reservoir.items]
        if len(set(window_ids)) != len(window_ids) or set(window_ids) & all_ids:
            raise ValueError("Duplicate event windows across or within splits")
        all_ids.update(window_ids)
        windows[split] = np.asarray([item[0] for item in reservoir.items], dtype=np.int64)
        stats["splits"][split] = {"available_windows": reservoir.seen, "selected_windows": len(reservoir.items),
            "host_count": len(hosts[split]), "hosts": hosts[split],
            "token_counts": dict(zip(TOKENS, np.bincount(windows[split].ravel(), minlength=len(TOKENS)).tolist())),
            "window_fingerprints_sha256": hashlib.sha256("\n".join(window_ids).encode()).hexdigest()}
    return windows, stats, manifest

def export_model(model, embedding, hidden):
    state = model.state_dict()
    keys = {"embedding": "embedding.weight", "weight_ih": "gru.weight_ih_l0", "weight_hh": "gru.weight_hh_l0",
        "bias_ih": "gru.bias_ih_l0", "bias_hh": "gru.bias_hh_l0", "output_weight": "output.weight", "output_bias": "output.bias"}
    return {"architecture": "gru", "feature_schema": FEATURE_SCHEMA, "tokens": TOKENS,
        "embedding_size": embedding, "hidden_size": hidden,
        **{name: state[key].detach().cpu().tolist() for name, key in keys.items()}}

def main():
    import numpy as np
    import torch
    from torch import nn
    import psutil
    from training.train import contexts, fit_baseline, baseline_nll, neural_nll, metrics, write_json

    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=ROOT / "training/data/lanl-v2-32mib")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "training/results/v2")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "training/cache/v2")
    parser.add_argument("--v1-models-dir", type=Path, default=ROOT / "training/results/v2/v1-original")
    parser.add_argument("--epochs", type=int, default=16)
    parser.add_argument("--patience", type=int, default=3)
    parser.add_argument("--max-train-windows", type=int, default=100000)
    parser.add_argument("--max-eval-windows", type=int, default=15000)
    parser.add_argument("--threads", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.epochs <= 40 or not 1 <= args.patience <= 10 or not 1 <= args.threads <= 4:
        parser.error("Bound epochs1..40, patience1..10, CPU threads1..4")
    out = args.output_dir.resolve()
    cache = args.cache_dir.resolve()
    if not out.is_relative_to((ROOT / "training/results").resolve()) or not cache.is_relative_to((ROOT / "training/cache").resolve()):
        parser.error("Experiment outputs and caches must stay inside this project's D: training/results and training/cache")
    models = out / "models"
    out.mkdir(parents=True, exist_ok=True)
    models.mkdir(exist_ok=True)
    if (out / "selection-freeze.json").exists():
        raise RuntimeError("Selection/test already frozen. Preserve it and use a new experiment rather than retune this holdout.")
    run_configuration = {key: str(value.resolve()) if isinstance(value, Path) else value for key, value in vars(args).items()}
    run_configuration.update({"seeds": list(SEEDS), "shapes": [list(shape) for shape in SHAPES]})
    configuration_path = out / "run-configuration.json"
    if configuration_path.exists() and json.loads(configuration_path.read_text()) != run_configuration:
        raise RuntimeError("This experiment contains different training configuration. Use a new experiment rather than mix candidate runs.")
    write_json(configuration_path, run_configuration)
    v1_original = out / "v1-original"
    if not v1_original.exists():
        source = args.v1_models_dir.resolve()
        if not source.exists():
            source = ROOT / "resources/models"
        original_model = BehavioralModel(source)
        if original_model.metadata["status"] != "available" or not original_model.metadata["version"].startswith("lanl2015-v1-"):
            raise ValueError("A preserved original v1 model is required for the fixed comparison")
        v1_original.mkdir()
        for original_file in source.glob("*.json"):
            shutil.copyfile(original_file, v1_original / original_file.name)
    torch.set_num_threads(args.threads)
    torch.use_deterministic_algorithms(True)
    started = time.perf_counter()
    reference = ROOT / "training/lanl-v2-manifest.json"
    cache.mkdir(parents=True, exist_ok=True)
    cache_key = {"reference_sha256": sha256(reference), "max_train": args.max_train_windows, "max_eval": args.max_eval_windows, "sampling_seed": 7301}
    key_path, cache_path = cache / "configuration.json", cache / "windows.npz"
    if key_path.exists() and cache_path.exists() and (cache / "splits.json").exists() and json.loads(key_path.read_text()) == cache_key:
        validate_dataset_manifest(args.data_dir, reference)
        stored = np.load(cache_path, allow_pickle=False)
        windows = {split: stored[split] for split in ("train", "validation", "test")}
        splits = json.loads((cache / "splits.json").read_text())
    else:
        windows, splits, _ = prepare(args.data_dir, reference, args.max_train_windows, args.max_eval_windows)
        write_json(cache / "splits.json", splits)
        np.savez_compressed(cache_path, **windows)
        write_json(key_path, cache_key)
    write_json(out / "splits.json", splits)
    print("Prepared fresh windows " + json.dumps({key: len(value) for key, value in windows.items()}), flush=True)
    train_x, train_y = contexts(windows["train"])
    val_x, val_y = contexts(windows["validation"])
    candidates = []

    class Predictor(nn.Module):
        def __init__(self, embedding, hidden):
            super().__init__()
            self.embedding = nn.Embedding(len(TOKENS), embedding)
            self.gru = nn.GRU(embedding, hidden, batch_first=True)
            self.output = nn.Linear(hidden, len(TOKENS))
        def forward(self, x):
            _, hidden = self.gru(self.embedding(x))
            return self.output(hidden[-1])

    for seed in SEEDS:
        baseline_name = f"baseline-seed{seed}"
        result_path = out / f"{baseline_name}.json"
        weights_path = models / f"{baseline_name}.json"
        if result_path.exists() and weights_path.exists():
            candidate = json.loads(result_path.read_text())
            if sha256(weights_path) != candidate["artifact_sha256"]:
                raise ValueError("Completed baseline artifact checksum changed")
        else:
            stamp = time.perf_counter()
            weights = fit_baseline(train_x, train_y, seed)
            validation, scores = metrics(baseline_nll(weights, val_x, val_y), windows["validation"])
            candidate = {"id": baseline_name, "architecture": "bag_centroid", "seed": seed,
                "artifact": weights_path.name, "validation": validation, "threshold": float(np.quantile(scores, .99)),
                "training_seconds": time.perf_counter() - stamp}
            write_json(weights_path, weights)
            candidate["artifact_sha256"] = sha256(weights_path)
            write_json(result_path, candidate)
        candidates.append(candidate)
        print(json.dumps(candidate), flush=True)
        for embedding, hidden in SHAPES:
            name = f"gru-e{embedding}-h{hidden}-seed{seed}"
            result_path = out / f"{name}.json"
            weights_path = models / f"{name}.json"
            if result_path.exists() and weights_path.exists() and (out / f"{name}.pt").exists():
                candidate = json.loads(result_path.read_text())
                if sha256(weights_path) != candidate["artifact_sha256"]:
                    raise ValueError("Completed neural artifact checksum changed")
                candidates.append(candidate)
                print("Reused completed validation run " + name, flush=True)
                continue
            np.random.seed(seed)
            torch.manual_seed(seed)
            model = Predictor(embedding, hidden)
            optimizer = torch.optim.Adam(model.parameters(), lr=.003)
            rng = np.random.default_rng(seed)
            history, best_state = [], None
            best, stale, best_epoch = float("inf"), 0, None
            stamp = time.perf_counter()
            for epoch in range(args.epochs):
                model.train()
                order = rng.permutation(len(train_x))
                total = 0.0
                for start in range(0, len(order), 512):
                    selected = order[start:start + 512]
                    x, y = torch.from_numpy(train_x[selected]), torch.from_numpy(train_y[selected])
                    optimizer.zero_grad()
                    loss = nn.functional.cross_entropy(model(x), y)
                    loss.backward()
                    nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                    optimizer.step()
                    total += float(loss.detach()) * len(selected)
                val_nll = neural_nll(model, val_x, val_y)
                loss = float(val_nll.mean())
                entry = {"epoch": epoch + 1, "train_next_event_nll_nats": total / len(train_x), "validation_next_event_nll_nats": loss}
                history.append(entry)
                print(json.dumps({"candidate": name, **entry}), flush=True)
                if loss < best - .0001:
                    best, stale, best_epoch = loss, 0, epoch + 1
                    best_state = {key: value.detach().clone() for key, value in model.state_dict().items()}
                else:
                    stale += 1
                if stale >= args.patience:
                    break
            model.load_state_dict(best_state)
            weights = export_model(model, embedding, hidden)
            validation, scores = metrics(neural_nll(model, val_x, val_y), windows["validation"])
            model.eval()
            with torch.no_grad():
                reference_probs = torch.softmax(model(torch.from_numpy(val_x[:32])), 1).numpy()
            error = max(float(np.max(np.abs(np.asarray(gru_predict(weights, row.tolist())) - expected)))
                        for row, expected in zip(val_x[:32], reference_probs))
            if error > 1e-6:
                raise ValueError("Export inference mismatch: " + name)
            write_json(weights_path, weights)
            candidate = {"id": name, "architecture": "gru", "seed": seed, "embedding_size": embedding,
                "hidden_size": hidden, "artifact": weights_path.name, "artifact_sha256": sha256(weights_path),
                "validation": validation, "threshold": float(np.quantile(scores, .99)), "selected_epoch": best_epoch,
                "training_seconds": time.perf_counter() - stamp, "export_maximum_probability_error": error,
                "epochs": history, "configuration": {"learning_rate": .003, "batch_size": 512, "patience": args.patience}}
            write_json(result_path, candidate)
            torch.save({"state_dict": best_state, "embedding_size": embedding, "hidden_size": hidden,
                "seed": seed, "selected_epoch": best_epoch, "feature_schema": FEATURE_SCHEMA}, out / f"{name}.pt")
            candidates.append(candidate)
            print("Completed validation " + name, flush=True)
    neural_candidates = [candidate for candidate in candidates if candidate["architecture"] == "gru"]
    baseline_candidates = [candidate for candidate in candidates if candidate["architecture"] == "bag_centroid"]
    selected_neural = min(neural_candidates, key=lambda candidate: candidate["validation"]["next_event_nll_nats"])
    selected_baseline = min(baseline_candidates, key=lambda candidate: candidate["validation"]["next_event_nll_nats"])
    selected = min(candidates, key=lambda candidate: candidate["validation"]["next_event_nll_nats"])
    freeze = {"selection_basis": "Minimum validation next-event NLL across fixed two capacities/two seeds; each epoch selected with patience3 and minimum improvement0.0001. Threshold99th-percentile maximum of8 targetNLLs. Test not used.",
        "selected_candidate": selected["id"], "selected_neural": selected_neural["id"], "selected_baseline": selected_baseline["id"],
        "candidate_artifacts": {candidate["id"]: candidate["artifact_sha256"] for candidate in candidates},
        "dataset_manifest_sha256": sha256(reference), "splits_sha256": sha256(out / "splits.json"),
        "v1_model_sha256": sha256(v1_original / "active.json"), "configuration": run_configuration}
    write_json(out / "selection-freeze.json", freeze)
    print("Selection and thresholds frozen BEFORE fresh test: " + selected["id"], flush=True)
    test_x, test_y = contexts(windows["test"])
    frozen_v1 = BehavioralModel(v1_original)
    if frozen_v1.metadata["status"] != "available":
        raise ValueError("Frozen v1 unavailable")
    final_results = []
    for candidate in candidates:
        weights = json.loads((models / candidate["artifact"]).read_text())
        if candidate["architecture"] == "bag_centroid":
            nll = baseline_nll(weights, test_x, test_y)
        else:
            model = Predictor(candidate["embedding_size"], candidate["hidden_size"])
            checkpoint = torch.load(out / f"{candidate['id']}.pt", map_location="cpu", weights_only=True)
            model.load_state_dict(checkpoint["state_dict"])
            nll = neural_nll(model, test_x, test_y)
        test_metrics, scores = metrics(nll, windows["test"], candidate["threshold"])
        final_results.append({key: candidate[key] for key in ("id", "architecture", "seed", "threshold", "validation", "training_seconds")} | {"test": test_metrics})
        np.savez_compressed(cache / f"{candidate['id']}-fresh-test.npz", nll=nll, window_max=scores)
    # Evaluate unchanged v1 using its existing PyTorch checkpoint rather than retuning.
    original = Predictor(8, 16)
    original_checkpoint = torch.load(ROOT / "training/results/temporal-checkpoint.pt", map_location="cpu", weights_only=True)
    original.load_state_dict(original_checkpoint["state_dict"])
    original_metrics, _ = metrics(neural_nll(original, test_x, test_y), windows["test"], frozen_v1.metadata["threshold"])
    best_weights = json.loads((models / selected["artifact"]).read_text())
    inference_times = []
    for row in test_x[:30]:
        stamp = time.perf_counter()
        (gru_predict if selected["architecture"] == "gru" else baseline_predict)(best_weights, row.tolist())
        inference_times.append((time.perf_counter() - stamp) * 1000)
    limitations = list(frozen_v1.metadata["limitations"])
    limitations[1] = "Expanded bounded2015 LANL enterprise host/network prefix; Windows application/session domain still differs."
    limitations[-1] = "Training aggregates host-wide events; a watched process session is a narrower stream. DNS-port and other rare token groups have very limited support despite the expanded data. Unknown NetFlow destination ports are common and differ from direct Windows observations."
    index = {"name": "Expanded LANL temporal GRU event predictor" if selected["architecture"] == "gru" else "Expanded LANL centroid event predictor", "version": "lanl2015-v2-" + selected["id"],
        "artifact": selected["artifact"], "sha256": selected["artifact_sha256"], "threshold": selected["threshold"],
        "limitations": limitations, "training_dataset": "LANL2015 expanded32MiB pinned proc/flows/dns prefixes; original-v1 time region excluded.",
        "selection": freeze["selection_basis"]}
    write_json(models / "active.json", index)
    runtime = BehavioralModel(models)
    if runtime.metadata["status"] != "available":
        raise ValueError("Experimental export not loadable by existing runtime")
    result = {"experiment": "lanl-v2-later-time", "configuration": freeze["configuration"], "objective": "Self-supervised next supported host-event token prediction",
        "selected_candidate": selected["id"], "selected_neural": selected_neural["id"], "selected_baseline": selected_baseline["id"],
        "selection_freeze_sha256": sha256(out / "selection-freeze.json"), "dataset_manifest_sha256": sha256(reference),
        "candidate_results": final_results, "unchanged_v1_fresh_test": original_metrics,
        "inference_one_prediction_ms": {"median": float(np.median(inference_times)), "p95": float(np.quantile(inference_times, .95)), "samples": len(inference_times)},
        "hardware": {"platform": platform.platform(), "processor": platform.processor(), "logical_cpus": os.cpu_count(), "device": "CPU", "threads": args.threads, "torch": torch.__version__, "numpy": np.__version__},
        "training_final_rss_mib": psutil.Process().memory_info().rss / 1024**2, "training_peak_rss_mib": None,
        "total_seconds": time.perf_counter() - started, "unavailable_detection_metrics": {"precision": None, "recall": None, "f1": None, "pr_auc": None, "false_positive_rate": None, "false_alerts_per_hour": None, "detection_latency": None,
            "reason": "No event-level attack/negative labels. These are prediction metrics; threshold exceedance counts unlabelled windows."},
        "promotion": "Not automatically promoted. Existing packaged/shipped resources/models remain v1 pending external scenario tests and review.", "limitations": limitations}
    write_json(out / "metrics.json", result)
    print(json.dumps(result), flush=True)

if __name__ == "__main__":
    main()
