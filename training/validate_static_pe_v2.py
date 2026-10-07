"""Verify research weight serialization against recorded scores, without refitting."""
from __future__ import annotations
import json
import time

try:
    from .static_pe_v2 import DATA,RESULTS,FEATURE_SCHEMA,sha256
except ImportError:
    from static_pe_v2 import DATA,RESULTS,FEATURE_SCHEMA,sha256

def validate():
    import lightgbm as lgb
    import numpy as np
    from scipy.special import expit
    from threadpoolctl import threadpool_limits
    begin=time.perf_counter()
    metrics=json.loads((RESULTS/"metrics.json").read_text(encoding="utf-8"))
    manifest=json.loads((RESULTS/"dataset-manifest.json").read_text(encoding="utf-8"))
    frozen=json.loads((RESULTS/"frozen-plan.json").read_text(encoding="utf-8"))
    if frozen["chosen_model"]!=metrics["chosen_model"]:raise ValueError("Frozen model choice mismatch")
    if metrics["feature_schema"]!=FEATURE_SCHEMA:raise ValueError("Unexpected feature schema")
    if sha256(RESULTS/"dataset-manifest.json")!=metrics["dataset_manifest_sha256"]:raise ValueError("Manifest integrity mismatch")
    artifacts={"lightgbm":"lightgbm-model.txt","linear_baseline":"linear-baseline.npz"}
    for name,path in artifacts.items():
        if sha256(RESULTS/path)!=metrics["model_artifact_sha256"][name]:raise ValueError("Model artifact integrity mismatch")
    if sha256(DATA/"test-features.npy")!=manifest["splits_detail"]["test"]["features_sha256"]:
        raise ValueError("Feature cache integrity mismatch")
    X=np.load(DATA/"test-features.npy",mmap_mode="r",allow_pickle=False)[:512]
    with np.load(DATA/"heldout-predictions.npz",allow_pickle=False) as recorded:
        expected={name:recorded[name][:len(X)].copy() for name in artifacts}
    with threadpool_limits(limits=2):
        model=lgb.Booster(model_file=str(RESULTS/"lightgbm-model.txt"))
        if model.num_feature()!=manifest["feature_count"]:raise ValueError("Model feature dimension mismatch")
        predictions={"lightgbm":model.predict(X,num_threads=2)}
        with np.load(RESULTS/"linear-baseline.npz",allow_pickle=False) as model:
            normalized=np.array(X,copy=True)
            normalized-=model["mean"]
            normalized/=model["scale"]
            predictions["linear_baseline"]=expit(normalized@model["coef"].T+model["intercept"]).reshape(-1)
    errors={name:float(np.max(np.abs(predictions[name]-expected[name]))) for name in artifacts}
    if any(not np.all(np.isfinite(value)) for value in predictions.values()):raise ValueError("Non-finite reloaded predictions")
    if any(value>5e-6 for value in errors.values()):raise ValueError("Reloaded artifact prediction mismatch")
    decisions={}
    for name in artifacts:
        decisions[name]={}
        for key in ["threshold","low_fpr_threshold"]:
            threshold=frozen["validation"][name][key]
            if threshold!=metrics["fitting"][name][key]:raise ValueError("Frozen threshold mismatch")
            count=int(np.count_nonzero((predictions[name]>=threshold)!=(expected[name]>=threshold)))
            decisions[name][key]=count
            if count:raise ValueError("Saved artifact changes a decision at a frozen threshold")
    result={"status":"passed","feature_schema":FEATURE_SCHEMA,"samples_compared":len(X),
            "max_absolute_prediction_error":errors,"tolerance":5e-6,
            "frozen_threshold_decision_disagreements":decisions,
            "model_artifact_sha256":metrics["model_artifact_sha256"],
            "elapsed_seconds":time.perf_counter()-begin,
            "method":"Read-only checksum verification and score reproduction from saved weights; no refit, threshold changes or new classification metrics"}
    (RESULTS/"artifact-validation.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps(result,indent=2))
    return result

if __name__=="__main__":validate()
