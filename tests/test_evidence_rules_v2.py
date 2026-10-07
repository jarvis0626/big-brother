"""Windows evidence references remain distinct from behavioral model output."""
from pathlib import Path
import pytest
from backend.explain import ExplanationEngine

ROOT = Path(__file__).resolve().parents[1]
SESSION = {"id": "recording-test", "mode": "recording", "ancestry_complete": False}

def evidence(kind="process_access", **details):
    return {"id": "observed-1", "kind": kind, "process_key": "source-guid",
            "pid": 123, "timestamp": "2026-10-07T00:00:00Z", "image": "C:\\lab\\helper.exe",
            "source": "recording:sysmon", "details": details}

def findings(event, model=None):
    return ExplanationEngine(ROOT / "resources").incidents(SESSION, [event], model, [])

@pytest.mark.parametrize("details", [
    {"TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1010"},
    {"target_image": "C:\\Windows\\System32\\LSASS.EXE", "granted_access": 0x20},
])
def test_memory_rights_rule_has_observed_citations_and_no_model_score(details):
    result = findings(evidence(**details))
    assert len(result) == 1
    report = result[0]
    assert report["score"] is None and report["score_kind"] == "rule_reference"
    assert report["model_version"] == "rules-2.0"
    assert report["event_ids"] == ["observed-1"]
    assert "lsass.exe" in report["explanation"]["observed"][0]["text"].lower()
    assert "does not establish credential extraction" in report["explanation"]["interpretations"][0]
    assert any("T1003/001" in doc["url"] for doc in report["explanation"]["documentation"])
    assert any("scenario labels" in text for text in report["explanation"]["missing"])

@pytest.mark.parametrize("target,rights", [
    ("C:\\Windows\\System32\\lsass.exe", "0x1000"),
    ("C:\\Windows\\System32\\lsass.exe", "unknown"),
    ("C:\\Windows\\System32\\lsass.exe", -1),
    ("C:\\Windows\\System32\\lsass.exe", True),
    ("C:\\Windows\\System32\\lsass.exe", 0x100000010),
    ("C:\\Windows\\System32\\notepad.exe", "0x1010"),
])
def test_query_only_unrelated_and_invalid_access_do_not_match(target, rights):
    assert findings(evidence(target_image=target, granted_access=rights)) == []

def test_remote_thread_reference_does_not_assert_malicious_execution():
    result = findings(evidence("remote_thread", target_image="C:\\lab\\target.exe"))
    assert len(result) == 1
    report = result[0]
    assert report["score_kind"] == "rule_reference" and report["score"] is None
    assert report["event_ids"] == ["observed-1"]
    assert "target.exe" in report["explanation"]["observed"][0]["text"]
    assert "does not establish malicious execution" in report["explanation"]["interpretations"][0]
    assert any("T1055" in doc["url"] for doc in report["explanation"]["documentation"])

def test_reference_and_model_finding_keep_separate_versions_and_scores():
    result = findings(evidence(target_image="lsass.exe", granted_access="0x10"),
                      {"above_threshold": True, "score": 8.5, "model_version": "trained-test",
                       "score_kind": "anomaly_score", "evidence_event_ids": ["observed-1"]})
    assert len(result) == 2
    assert {(item["model_version"], item["score"]) for item in result} == {("rules-2.0", None), ("trained-test", 8.5)}
