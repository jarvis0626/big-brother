"""Small trained categorical models with standard-library inference only.

Anomaly scores are negative log likelihood in nats, never malware probabilities.
Model files are required: missing or incompatible artifacts expose unavailable.
"""
from __future__ import annotations
import collections
from datetime import datetime,timezone
import hashlib
import json
import math
from pathlib import Path

FEATURE_SCHEMA = "lanl-host-events-port-category-v1"
TOKENS = ["process_start", "process_end", "dns", "network_web", "network_smb",
          "network_remote", "network_dns", "network_other_service", "network_high_port", "network_unknown_port"]
CONTEXT = 16
TARGETS = 8

def port_token(port):
    try:
        value = int(port)
    except (TypeError, ValueError, OverflowError):
        return 9
    if not 0 <= value <= 65535:
        return 9
    if value in {80, 443, 8080, 8443}:
        return 3
    if value in {139, 445}:
        return 4
    if value in {22, 3389}:
        return 5
    if value == 53:
        return 6
    return 7 if value < 1024 else 8

def event_token(event):
    kind = event.get("kind")
    if kind == "process_start": return 0
    if kind == "process_end": return 1
    if kind == "dns": return 2
    if kind == "network":
        details = event.get("details") or {}
        if details.get("snapshot") and str(details.get("protocol", "")).lower() == "tcp" and str(details.get("status", "")).upper() != "ESTABLISHED":
            return None
        return port_token(details.get("destination_port", details.get("dest_port", details.get("remote_port"))))
    return None

def _event_order(event):
    value=event.get("timestamp", "")
    try:
        if isinstance(value,(int,float)):
            stamp=float(value)
        else:
            parsed=datetime.fromisoformat(str(value).replace("Z","+00:00"))
            if parsed.tzinfo is None:parsed=parsed.replace(tzinfo=timezone.utc)
            stamp=parsed.timestamp()
        if not math.isfinite(stamp):stamp=float("inf")
    except (ValueError,TypeError,OverflowError,OSError):
        stamp=float("inf")
    return stamp,str(event.get("id",""))

def histogram(tokens):
    result = [0.0] * len(TOKENS)
    for token in tokens:
        result[token] += 1.0 / max(1,len(tokens))
    return result

def _dot(row, vector):
    return sum(a*b for a,b in zip(row,vector))

def _sigmoid(value):
    value = max(-60.0,min(60.0,value))
    return 1.0/(1.0+math.exp(-value))

def baseline_predict(weights, tokens):
    feature = histogram(tokens)
    index = min(range(len(weights["centroids"])),
                key=lambda i: sum((a-b)**2 for a,b in zip(feature,weights["centroids"][i])))
    return weights["probabilities"][index]

def gru_predict(weights, tokens):
    state = [0.0]*weights["hidden_size"]
    size = len(state)
    for token in tokens:
        embedded = weights["embedding"][token]
        gates_input = [_dot(row,embedded)+bias for row,bias in zip(weights["weight_ih"],weights["bias_ih"])]
        gates_hidden = [_dot(row,state)+bias for row,bias in zip(weights["weight_hh"],weights["bias_hh"])]
        reset = [_sigmoid(gates_input[i]+gates_hidden[i]) for i in range(size)]
        update = [_sigmoid(gates_input[size+i]+gates_hidden[size+i]) for i in range(size)]
        candidate = [math.tanh(gates_input[2*size+i]+reset[i]*gates_hidden[2*size+i]) for i in range(size)]
        state = [(1-update[i])*candidate[i]+update[i]*state[i] for i in range(size)]
    logits = [_dot(row,state)+bias for row,bias in zip(weights["output_weight"],weights["output_bias"])]
    maximum = max(logits)
    exp = [math.exp(value-maximum) for value in logits]
    denominator = sum(exp)
    return [value/denominator for value in exp]

def _matrix(value, rows, columns):
    if not isinstance(value,list) or len(value)!=rows or any(not isinstance(row,list) or len(row)!=columns for row in value):
        raise ValueError("Incompatible model matrix dimensions")
    if any(not isinstance(x,(int,float)) or not math.isfinite(x) for row in value for x in row):
        raise ValueError("Nonfinite model weights")

class BehavioralModel:
    def __init__(self, resources_models_dir):
        path=Path(resources_models_dir)
        if (path/"models").is_dir():path=path/"models"
        self.weights=None
        self.metadata={"name":"Trained model", "version":"unavailable", "status":"unavailable", "threshold":None,
                       "limitations":["Model artifact is missing or incompatible. Model scoring is unavailable."]}
        try:
            index_path=path/"active.json"
            if index_path.stat().st_size>128*1024:raise ValueError("Oversized index")
            index=json.loads(index_path.read_text(encoding="utf8"))
            filename=index["artifact"]
            if Path(filename).name!=filename:raise ValueError("Invalid artifact filename")
            artifact=path/filename
            if artifact.stat().st_size>1024*1024:raise ValueError("Oversized model")
            data=artifact.read_bytes()
            if len(data)>1024*1024:raise ValueError("Oversized model")
            if hashlib.sha256(data).hexdigest()!=index["sha256"]:raise ValueError("Model checksum mismatch")
            weights=json.loads(data)
            if weights["feature_schema"]!=FEATURE_SCHEMA or weights["tokens"]!=TOKENS:
                raise ValueError("Incompatible feature schema")
            threshold=float(index["threshold"])
            if not math.isfinite(threshold) or threshold<0:raise ValueError("Invalid threshold")
            architecture=weights["architecture"]
            if architecture=="bag_centroid":
                count=len(weights["centroids"])
                if not 1<=count<=32:raise ValueError("Invalid centroid count")
                _matrix(weights["centroids"],count,len(TOKENS))
                _matrix(weights["probabilities"],count,len(TOKENS))
                for probs in weights["probabilities"]:
                    if min(probs)<=0 or abs(sum(probs)-1)>1e-6:raise ValueError("Invalid distribution")
            elif architecture=="gru":
                hidden=weights["hidden_size"];embedding=weights["embedding_size"]
                if not isinstance(hidden,int) or not 1<=hidden<=32 or not isinstance(embedding,int) or not 1<=embedding<=16:
                    raise ValueError("Invalid neural shape")
                for key,rows,columns in [("embedding",len(TOKENS),embedding),("weight_ih",hidden*3,embedding),
                    ("weight_hh",hidden*3,hidden),("output_weight",len(TOKENS),hidden)]:
                    _matrix(weights[key],rows,columns)
                for key,size in [("bias_ih",hidden*3),("bias_hh",hidden*3),("output_bias",len(TOKENS))]:
                    _matrix([weights[key]],1,size)
            else:raise ValueError("Unsupported trained architecture")
            self.weights=weights
            self.metadata={k:index[k] for k in ("name","version","threshold","limitations")}
            self.metadata.update({"status":"available","feature_schema":FEATURE_SCHEMA,"architecture":architecture,
                                  "score_kind":"anomaly negative log likelihood (nats)","supported_kinds":["process_start","process_end","network","dns"],
                                  "artifact_sha256":index["sha256"],"training_dataset":index["training_dataset"]})
            self.metadata.update({"applicability":"reference_only", "required_context_events":CONTEXT,
                                  "inference_policy":"windows-reference-full-context-v1",
                                  "reference_domain":"2015 enterprise host activity; not calibrated for Windows application sessions"})
        except (OSError,ValueError,TypeError,KeyError) as exc:
            self.metadata["reason"]=str(exc)

    def predict(self, context):
        if self.weights is None:raise RuntimeError("Trained model unavailable")
        context=list(context)[-CONTEXT:]
        if not context or any(not isinstance(x,int) or not 0<=x<len(TOKENS) for x in context):
            raise ValueError("Context must contain valid observed tokens")
        return (baseline_predict if self.weights["architecture"]=="bag_centroid" else gru_predict)(self.weights,context)

    def score(self, events):
        result={"score":None,"score_kind":"anomaly negative log likelihood (nats)","model_version":self.metadata["version"],
                "threshold":self.metadata["threshold"],"above_threshold":False,"evidence_event_ids":[],"selected_evidence":[],
                "limitations":list(self.metadata["limitations"]),"status":self.metadata["status"]}
        if self.weights is None:return result
        selected=[]
        ignored=collections.Counter()
        excluded=collections.Counter()
        for event in sorted(events,key=_event_order):
            token=event_token(event)
            if token is None:
                ignored[str(event.get("kind"))]+=1
                if event.get("kind") == "network":excluded["non_established_tcp_snapshot"]+=1
            else:selected.append((event,token))
        selected=selected[-(CONTEXT+TARGETS):]
        result["features"]={"supported_events":len(selected),"ignored_kinds":dict(ignored),"context_events":min(CONTEXT,max(0,len(selected)-1)),
                            "token_counts":dict(collections.Counter(TOKENS[token] for _,token in selected)),
                            "excluded_observation_reasons":dict(excluded),"required_context_events":CONTEXT}
        if len(selected)<2:
            result["status"]="insufficient_evidence"
            return result
        if len(selected) <= CONTEXT:
            result["status"]="insufficient_context"
            result["limitations"].append("Reference scoring needs 16 preceding supported events. No score or model note is produced during warm-up.")
            return result
        best=(-1.0,None,None)
        for i in range(max(CONTEXT,len(selected)-TARGETS),len(selected)):
            context=[x[1] for x in selected[max(0,i-CONTEXT):i]]
            probs=self.predict(context)
            nll=-math.log(max(1e-12,probs[selected[i][1]]))
            if nll>best[0]:best=(nll,i,context)
        score,index,context=best
        result["score"]=score
        result["above_threshold"]=score>self.metadata["threshold"]
        supporting=selected[max(0,index-CONTEXT):index+1]
        result["evidence_event_ids"]=[str(event["id"]) for event,_ in supporting if event.get("id") is not None]
        result["selected_evidence"]=[{"event_id":str(selected[index][0].get("id","")),"token":TOKENS[selected[index][1]],"negative_log_likelihood":score}]
        result["reference_context"]={"target_category":TOKENS[selected[index][1]],
                                     "preceding_category_counts":dict(collections.Counter(TOKENS[token] for token in context))}
        if len(context)<CONTEXT:result["limitations"].append("Short event context; held-out evaluation used16 preceding supported events.")
        return result

Model=BehavioralModel
