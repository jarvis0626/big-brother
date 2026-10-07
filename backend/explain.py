"""Evidence-first explanations. Event text cannot instruct the application."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re


def tokens(text):
    return re.findall(r"[a-z0-9]{2,}", str(text).lower())[:4096]


class KnowledgeIndex:
    def __init__(self, path: Path):
        corpus = json.loads(path.read_text(encoding="utf-8"))
        self.version = corpus["version"]
        self.documents = corpus["documents"]
        self.terms = [Counter(tokens(doc["title"] + " " + doc["text"] + " " + " ".join(doc.get("tags", [])))) for doc in self.documents]
        self.document_frequency = Counter(term for terms in self.terms for term in terms)

    def retrieve(self, query, limit=3):
        query_terms = set(tokens(query))
        scores = []
        for index, terms in enumerate(self.terms):
            score = sum(math.log(1 + len(self.documents) / (1 + self.document_frequency[term]))
                        * terms.get(term, 0) / (1 + terms.get(term, 0)) for term in query_terms)
            if score > 0:
                doc = self.documents[index]
                scores.append((score, {"id": doc["id"], "title": doc["title"], "url": doc["url"],
                                       "version": doc["source_version"], "retrieved_at": doc["retrieved_at"],
                                       "summary": doc["text"], "corpus_version": self.version}))
        return [doc for _, doc in sorted(scores, key=lambda pair: pair[0], reverse=True)[:limit]]


def safe(value, maximum=220):
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(value or "Unknown"))[:maximum]


def observed(event):
    name = safe(event.get("image", "").replace("\\", "/").split("/")[-1] or f"Process {event.get('pid')}")
    details = event.get("details", {})
    kind = event["kind"]
    if kind == "process_start":
        text = f"{name} was observed running with process ID {event['pid']}."
        if event.get("parent_key"):
            text += " The recorded parent relationship links it to the watched chain."
    elif kind == "process_end":
        text = f"{name} was recorded as having ended."
    elif kind == "network":
        text = f"{name} had a recorded connection to {safe(details.get('destination_ip') or details.get('DestinationIp'))}:{safe(details.get('destination_port') or details.get('DestinationPort'))}."
        if details.get("snapshot"):
            text += " This is a connection snapshot; its direction and contents were not recorded."
    elif kind == "dns":
        text = f"{name} made a recorded DNS query for {safe(details.get('query') or details.get('QueryName'))}."
    elif kind == "registry":
        text = f"{name} had a recorded Registry change at {safe(details.get('target') or details.get('TargetObject'))}."
    elif kind in ("file_create", "file_delete"):
        verb = "creation" if kind == "file_create" else "deletion"
        text = f"{name} had a recorded file {verb} at {safe(details.get('target') or details.get('TargetFilename'))}."
    elif kind == "process_access":
        text = f"{name} had a recorded access event involving {safe(details.get('TargetImage') or details.get('target_image') or details.get('target'))}."
    elif kind == "remote_thread":
        text = f"{name} had a recorded thread-creation event in {safe(details.get('TargetImage') or details.get('target_image') or details.get('target'))}."
    elif kind == "image_load":
        text = f"{name} had a recorded module load for {safe(details.get('ImageLoaded') or details.get('image_loaded') or details.get('target'))}."
    else:
        text = f"{name} produced a recorded {safe(kind)} event."
    if event.get("source", "").startswith("replay"):
        text = "Fabricated replay: " + text
    return {"text": text, "event_ids": [event["id"]]}


class ExplanationEngine:
    def __init__(self, resources: Path):
        self.knowledge = KnowledgeIndex(resources / "knowledge.json")

    def explain(self, events, title, interpretation, query, session, coverage):
        # Retrieve the bounded observed subgraph first, then general documentation.
        selected = sorted(events, key=lambda event: (event["timestamp"], event["id"]))[-24:]
        missing = ["Recorded connections do not reveal encrypted traffic contents or prove data theft.",
                   "The app does not determine software trust or guarantee that activity is safe."]
        if not session["ancestry_complete"]:
            missing.append("Activity and ancestry before monitoring began may be missing.")
        if any(event.get("uncertain") for event in selected):
            missing.append("Some evidence came from snapshots; brief processes or connections may be missed and times may be approximate.")
        if any(item["status"] in ("unavailable", "configuration_unknown") for item in coverage):
            missing.append("File, Registry, DNS or other event coverage may be unavailable or excluded by collector configuration.")
        if session["mode"] == "replay":
            missing.append("This session is fabricated demonstration telemetry and is excluded from model evaluation.")
        if session["mode"] == "recording":
            missing.append("Imported recording: scenario labels do not identify every event as malicious; source metadata is not authenticated by import.")
        return {"observed": [observed(event) for event in selected],
                "interpretations": [interpretation], "missing": missing,
                "suggested": ["Check whether these actions match the program's expected purpose.",
                              "Review the recorded executable paths, parent chain and supporting events.",
                              "Verify publisher signatures and destinations before deciding how to respond."],
                "documentation": self.knowledge.retrieve(query)}

    def incidents(self, session, events, model_result, coverage):
        findings = []
        registry = [event for event in events if event["kind"] == "registry" and any(
            marker in str(event.get("details", {}).get("target") or event.get("details", {}).get("TargetObject", "")).lower()
            for marker in ("\\currentversion\\run", "\\startup", "bootexecute"))]
        if registry:
            findings.append(("Startup configuration changed", "medium", registry,
                             "Startup locations can be used by legitimate installers or for persistence. The change alone does not establish malicious intent.",
                             "registry startup persistence run keys T1547.001", "rule_reference", None, "rules-1.0"))
        ends = {event["process_key"]: event for event in events if event["kind"] == "process_end"}
        starts = {event["process_key"]: event for event in events if event["kind"] == "process_start"}
        surviving = []
        for event in events:
            start = starts.get(event["process_key"])
            parent = start.get("parent_key") if start else event.get("parent_key")
            end = ends.get(parent)
            if event["kind"] == "network" and end and end["timestamp"] < event["timestamp"]:
                surviving.extend([start, end, event] if start else [end, event])
        if surviving:
            unique = list({event["id"]: event for event in surviving}.values())
            findings.append(("A child continued connecting after its parent ended", "medium", unique,
                             "Background helpers commonly outlive their launchers. Inspect the child program and destination when this is unexpected.",
                             "process termination network connection Sysmon", "rule_reference", None, "rules-1.0"))
        memory_access = []
        for event in events:
            if event["kind"] != "process_access": continue
            details = event.get("details") or {}
            target = str(details.get("TargetImage") or details.get("target_image") or details.get("target", "")).replace("\\", "/").split("/")[-1].lower()
            value = details.get("GrantedAccess", details.get("granted_access", ""))
            try:
                access = value if isinstance(value, int) and not isinstance(value, bool) else int(str(value)[:64], 0)
            except (ValueError, TypeError):
                continue
            if target == "lsass.exe" and 0 <= access <= 0xffffffff and access & 0x30:
                memory_access.append(event)
        if memory_access:
            findings.append(("Memory-capable access to the sign-in process was recorded", "medium", memory_access,
                             "The recorded access rights include reading or writing process memory for lsass.exe. Security and administrative software can do this legitimately; verify the source program. The event alone does not establish credential extraction.",
                             "LSASS memory access rights PROCESS_VM_READ PROCESS_VM_WRITE T1003.001", "rule_reference", None, "rules-2.0"))
        threads = [event for event in events if event["kind"] == "remote_thread"]
        if threads:
            findings.append(("A thread was created in another process", "medium", threads,
                             "Recorded thread creation in another process can occur during debugging or instrumentation and can also support process injection. Verify the source and target programs; this event does not establish malicious execution.",
                             "Sysmon CreateRemoteThread Event8 process injection T1055", "rule_reference", None, "rules-2.0"))
        if model_result and model_result.get("above_threshold"):
            ids = set(model_result.get("evidence_event_ids") or [event["id"] for event in events])
            evidence = [event for event in events if event["id"] in ids]
            if evidence:
                findings.append(("Activity differs from the trained reference", "low", evidence,
                                 "The trained model rated this activity as unusual relative to its training sample. Domain differences and incomplete telemetry can cause false alerts; this score is not a probability of maliciousness.",
                                 "process network telemetry Sysmon", model_result.get("score_kind", "anomaly_score"),
                                 model_result["score"], model_result["model_version"]))
        output = []
        for title, severity, evidence, interpretation, query, score_kind, score, version in findings:
            identity = f"{session['id']}:{title}"
            output.append({"id": "incident_" + hashlib.sha256(identity.encode()).hexdigest()[:20],
                           "session_id": session["id"], "title": title, "severity": severity, "score": score,
                           "score_kind": score_kind, "model_version": version,
                           "event_ids": [event["id"] for event in evidence],
                           "explanation": self.explain(evidence, title, interpretation, query, session, coverage)})
        return output
