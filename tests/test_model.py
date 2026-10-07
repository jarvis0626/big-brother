import hashlib
import json
import math
from pathlib import Path
import shutil

from backend.model import BehavioralModel,FEATURE_SCHEMA,TOKENS,event_token,_event_order

ROOT=Path(__file__).resolve().parents[1]

def test_missing_model_is_unavailable_and_does_not_substitute_rules(tmp_path):
    model=BehavioralModel(tmp_path)
    assert model.metadata["status"]=="unavailable"
    result=model.score([{"kind":"registry","id":"r","details":{"key":"Run"}}])
    assert result["status"]=="unavailable"
    assert result["above_threshold"] is False

def test_unsupported_file_registry_events_cannot_influence_model():
    assert event_token({"kind":"file_create","details":{"path":"secrets.txt"}}) is None
    assert event_token({"kind":"registry","details":{"key":"Run"}}) is None
    assert event_token({"kind":"process_access"}) is None
    assert event_token({"kind":"network","details":{"destination_port":443}})==3

def test_model_orders_mixed_fractional_iso_timestamps_correctly():
    early={"id":"start","timestamp":"2026-10-07T00:00:00Z"}
    later={"id":"child","timestamp":"2026-10-07T00:00:00.500Z"}
    assert sorted([later,early],key=_event_order)==[early,later]

def test_real_trained_model_loads_and_scores_finite_values():
    model=BehavioralModel(ROOT/"resources/models")
    assert model.metadata["status"]=="available",model.metadata
    assert model.metadata["feature_schema"]==FEATURE_SCHEMA
    active=json.loads((ROOT/"resources/models/active.json").read_text())
    assert model.metadata["version"]==active["version"]
    probs=model.predict([0,3,2,4,1]*3+[0])
    assert len(probs)==len(TOKENS)
    assert math.isclose(sum(probs),1,abs_tol=1e-6)
    assert min(probs)>0
    events=[{"id":str(i),"timestamp":f"2026-10-07T00:00:{i:02d}Z","kind":"network","details":{"destination_port":443}} for i in range(24)]
    result=model.score(events)
    assert math.isfinite(result["score"])
    assert result["score_kind"]=="anomaly negative log likelihood (nats)"
    assert set(result["evidence_event_ids"])<=set(e["id"] for e in events)
    unsupported=events+[{"id":"unscored","timestamp":"2026-10-07T00:01:00Z","kind":"registry","details":{"key":"Run"}}]
    assert model.score(unsupported)["score"]==result["score"]

def test_model_checksum_and_schema_mismatch_are_unavailable(tmp_path):
    source=ROOT/"resources/models"
    for path in source.glob("*.json"):shutil.copy2(path,tmp_path/path.name)
    index=json.loads((tmp_path/"active.json").read_text())
    artifact=tmp_path/index["artifact"]
    data=json.loads(artifact.read_text())
    data["feature_schema"]="unsupported_schema"
    artifact.write_text(json.dumps(data),encoding="utf8")
    assert BehavioralModel(tmp_path).metadata["status"]=="unavailable"
    index["sha256"]=hashlib.sha256(artifact.read_bytes()).hexdigest()
    (tmp_path/"active.json").write_text(json.dumps(index),encoding="utf8")
    model=BehavioralModel(tmp_path)
    assert model.metadata["status"]=="unavailable"
    assert "schema" in model.metadata["reason"]

def test_saved_dataset_has_no_host_time_or_window_identity_leakage():
    splits=json.loads((ROOT/"training/results/splits.json").read_text())
    identities=json.loads((ROOT/"training/results/window-identities.json").read_text())
    a,b=splits["time_boundaries"]
    hosts={s:{row["host"] for row in splits["splits"][s]["hosts"]} for s in identities}
    assert not(hosts["train"]&hosts["validation"] or hosts["train"]&hosts["test"] or hosts["validation"]&hosts["test"])
    ids={s:set(v) for s,v in identities.items()}
    assert not(ids["train"]&ids["validation"] or ids["train"]&ids["test"] or ids["validation"]&ids["test"])
    for split,rows in splits["splits"].items():
        assert rows["selected_windows"]>=10
        for row in rows["hosts"]:
            if split=="train":assert row["max_time"]<a
            elif split=="validation":assert a<=row["min_time"]<=row["max_time"]<b
            else:assert row["min_time"]>=b

def test_actual_export_matches_torch_and_no_classification_claims():
    metrics=json.loads((ROOT/"training/results/metrics.json").read_text())
    assert metrics["export_maximum_probability_error"]<1e-6
    assert metrics["baseline"]["test"]["prediction_count"]>0
    assert metrics["temporal"]["test"]["prediction_count"]>0
    for key in ("precision","recall","f1","pr_auc","false_positive_rate"):
        assert metrics["unavailable_metrics"][key] is None
