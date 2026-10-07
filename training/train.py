"""Reproducible real telemetry predictive baseline/temporal experiment.

CPU training dependencies are separate from shipped standard-library inference.
No labels, retrieval answers, fabricated fixtures or OpTC transformations are used.
"""
from __future__ import annotations
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import time
import numpy as np
import torch
from torch import nn
from sklearn.cluster import MiniBatchKMeans

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from backend.model import CONTEXT,TARGETS,TOKENS,FEATURE_SCHEMA,port_token,BehavioralModel,gru_predict

def digest(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest()

def host_bucket(host):
    return int(hashlib.sha256(host.encode()).hexdigest()[:8],16)%10

def split_for(host, stamp, end):
    bucket=host_bucket(host)
    a=int(end*.6);b=int(end*.8)
    if bucket<6 and 1<=stamp<a:return "train"
    if 6<=bucket<8 and a<=stamp<b:return "validation"
    if bucket>=8 and b<=stamp<=end:return "test"
    return None

def prepare(data,max_train,max_eval,seed):
    manifest=json.loads((data/"lanl-manifest.json").read_text(encoding="utf8"))
    end=min(p["maximum_time"] for p in manifest["partitions"])
    groups={split:collections.defaultdict(list) for split in ("train","validation","test")}
    stats={"common_time_seconds":[1,end],"time_boundaries":[int(end*.6),int(end*.8)],"records_read":{},"duplicate_rows_excluded":{},"malformed_records_excluded":{},"splits":{}}
    for part in manifest["partitions"]:
        kind=part["kind"]
        file=data/("lanl-"+kind+".txt")
        if digest(file)!=part["text_sha256"]:raise ValueError("Dataset checksum mismatch")
        seen=set();duplicates=malformed=read=0
        with file.open("r",encoding="ascii") as source:
            for line_no,line in enumerate(source):
                read+=1
                fields=line.rstrip("\n").split(",")
                try:
                    stamp=int(fields[0])
                    if not 1<=stamp<=end:continue
                    if kind=="proc" and len(fields)==5:
                        host=fields[2]
                        if fields[4] not in {"Start","End"}:continue
                        token=0 if fields[4]=="Start" else 1
                    elif kind=="flows" and len(fields)==9:
                        host=fields[2];token=port_token(fields[5])
                    elif kind=="dns" and len(fields)==3:
                        host=fields[1];token=2
                    else:malformed+=1;continue
                    if not host or len(host)>100:malformed+=1;continue
                except (ValueError,IndexError):malformed+=1;continue
                fingerprint=hashlib.sha256((kind+":"+line).encode()).digest()
                if fingerprint in seen:duplicates+=1;continue
                seen.add(fingerprint)
                split=split_for(host,stamp,end)
                if split:groups[split][host].append((stamp,kind,line_no,token,fingerprint))
        stats["records_read"][kind]=read
        stats["duplicate_rows_excluded"][kind]=duplicates
        stats["malformed_records_excluded"][kind]=malformed
    rng=np.random.default_rng(seed)
    prepared={};split_ids={};all_hosts=set();all_ids=set()
    for split,hosts in groups.items():
        windows=[];ids=[];hoststats=[]
        for host,events in sorted(hosts.items()):
            events.sort(key=lambda x:(x[0],x[1],x[2]))
            count=0
            for start in range(0,len(events)-CONTEXT-TARGETS+1,CONTEXT+TARGETS):
                window=events[start:start+CONTEXT+TARGETS]
                fingerprint=hashlib.sha256(b"".join(e[4] for e in window)).hexdigest()
                if fingerprint in all_ids:raise ValueError("Duplicate event window spans splits")
                all_ids.add(fingerprint)
                windows.append([e[3] for e in window]);ids.append(fingerprint);count+=1
            if count:
                if host in all_hosts:raise ValueError("Host leakage")
                all_hosts.add(host)
                hoststats.append({"host":host,"min_time":events[0][0],"max_time":events[-1][0],"windows":count})
        limit=max_train if split=="train" else max_eval
        selected=np.sort(rng.choice(len(windows),min(limit,len(windows)),replace=False))
        array=np.asarray(windows,dtype=np.int64)[selected]
        if len(array)<10:raise ValueError("Too few held-out windows for meaningful evaluation")
        prepared[split]=array;split_ids[split]=[ids[int(i)] for i in selected]
        stats["splits"][split]={"available_windows":len(windows),"selected_windows":len(array),"hosts":hoststats,
            "token_counts":dict(zip(TOKENS,np.bincount(array.ravel(),minlength=len(TOKENS)).tolist())),
            "window_fingerprints_sha256":hashlib.sha256("\n".join(split_ids[split]).encode()).hexdigest()}
    # No related event window is divided:24 consecutive events are kept together.
    return prepared,stats,split_ids,manifest

def contexts(windows):
    x=np.stack([windows[:,i-CONTEXT:i] for i in range(CONTEXT,CONTEXT+TARGETS)],axis=1)
    return x.reshape(-1,CONTEXT),windows[:,CONTEXT:].reshape(-1)

def features(x):
    return np.stack([(x==i).mean(1) for i in range(len(TOKENS))],axis=1)

def fit_baseline(x,y,seed):
    feature=features(x)
    kmeans=MiniBatchKMeans(n_clusters=8,random_state=seed,n_init=3,batch_size=1024,max_iter=100)
    assignment=kmeans.fit_predict(feature)
    counts=np.ones((8,len(TOKENS)),dtype=np.float64)
    np.add.at(counts,(assignment,y),1)
    probabilities=counts/counts.sum(1,keepdims=True)
    return {"architecture":"bag_centroid","feature_schema":FEATURE_SCHEMA,"tokens":TOKENS,
            "centroids":kmeans.cluster_centers_.tolist(),"probabilities":probabilities.tolist()}

def baseline_nll(weights,x,y):
    feature=features(x);centroids=np.asarray(weights["centroids"])
    distance=((feature[:,None,:]-centroids[None,:,:])**2).sum(2)
    assigned=distance.argmin(1)
    return -np.log(np.asarray(weights["probabilities"])[assigned,y])

class TemporalPredictor(nn.Module):
    def __init__(self):
        super().__init__()
        self.embedding=nn.Embedding(len(TOKENS),8)
        self.gru=nn.GRU(8,16,batch_first=True)
        self.output=nn.Linear(16,len(TOKENS))
    def forward(self,x):
        _,hidden=self.gru(self.embedding(x))
        return self.output(hidden[-1])

def neural_nll(model,x,y):
    model.eval();scores=[]
    with torch.no_grad():
        for start in range(0,len(x),1024):
            inputs=torch.from_numpy(x[start:start+1024]);targets=torch.from_numpy(y[start:start+1024])
            scores.extend(nn.functional.cross_entropy(model(inputs),targets,reduction="none").tolist())
    return np.asarray(scores)

def export_neural(model):
    state=model.state_dict()
    keys={"embedding":"embedding.weight","weight_ih":"gru.weight_ih_l0","weight_hh":"gru.weight_hh_l0",
          "bias_ih":"gru.bias_ih_l0","bias_hh":"gru.bias_hh_l0","output_weight":"output.weight","output_bias":"output.bias"}
    return {"architecture":"gru","feature_schema":FEATURE_SCHEMA,"tokens":TOKENS,"embedding_size":8,"hidden_size":16,
            **{k:state[v].detach().cpu().tolist() for k,v in keys.items()}}

def metrics(nll,windows,threshold=None):
    scores=nll.reshape(len(windows),TARGETS).max(1)
    result={"next_event_nll_nats":float(nll.mean()),"perplexity":float(np.exp(nll.mean())),
            "mean_window_max_nll_nats":float(scores.mean()),"prediction_count":len(nll),"window_count":len(windows)}
    if threshold is not None:
        result.update({"threshold_exceedance_windows":int((scores>threshold).sum()),
                       "threshold_exceedance_fraction":float((scores>threshold).mean()),"denominator":"disjoint24-event windows; no negative-class labels available"})
    return result,scores

def write_json(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(data,indent=2,allow_nan=False)+"\n",encoding="utf8")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--epochs",type=int,default=8)
    parser.add_argument("--seed",type=int,default=1984)
    parser.add_argument("--max-train-windows",type=int,default=10000)
    parser.add_argument("--max-eval-windows",type=int,default=3000)
    args=parser.parse_args()
    np.random.seed(args.seed);torch.manual_seed(args.seed);torch.set_num_threads(2)
    torch.use_deterministic_algorithms(True)
    started=time.perf_counter()
    windows,splits,window_ids,manifest=prepare(ROOT/"training/data",args.max_train_windows,args.max_eval_windows,args.seed)
    result_dir=ROOT/"training/results";result_dir.mkdir(parents=True,exist_ok=True)
    write_json(result_dir/"splits.json",splits)
    write_json(result_dir/"window-identities.json",window_ids)
    print("Prepared",{k:len(v) for k,v in windows.items()},flush=True)
    train_x,train_y=contexts(windows["train"]);val_x,val_y=contexts(windows["validation"])
    baseline_started=time.perf_counter();baseline=fit_baseline(train_x,train_y,args.seed)
    baseline_seconds=time.perf_counter()-baseline_started
    baseline_val_nll=baseline_nll(baseline,val_x,val_y)
    baseline_val,baseline_val_scores=metrics(baseline_val_nll,windows["validation"])
    model=TemporalPredictor();optimizer=torch.optim.Adam(model.parameters(),lr=.005)
    history=[];best=float("inf");best_state=None
    neural_started=time.perf_counter()
    generator=np.random.default_rng(args.seed)
    for epoch in range(args.epochs):
        model.train();order=generator.permutation(len(train_x));loss_sum=0
        for start in range(0,len(order),256):
            selected=order[start:start+256]
            x=torch.from_numpy(train_x[selected]);y=torch.from_numpy(train_y[selected])
            optimizer.zero_grad();loss=nn.functional.cross_entropy(model(x),y)
            loss.backward();nn.utils.clip_grad_norm_(model.parameters(),1.0);optimizer.step()
            loss_sum+=float(loss.detach())*len(selected)
        val_nll=neural_nll(model,val_x,val_y)
        entry={"epoch":epoch+1,"train_next_event_nll_nats":loss_sum/len(train_x),"validation_next_event_nll_nats":float(val_nll.mean())}
        history.append(entry);print(json.dumps(entry),flush=True)
        if entry["validation_next_event_nll_nats"]<best:
            best=entry["validation_next_event_nll_nats"]
            best_state={k:v.detach().clone() for k,v in model.state_dict().items()}
    model.load_state_dict(best_state)
    neural_seconds=time.perf_counter()-neural_started
    neural=export_neural(model)
    # Export preservation checked against PyTorch before shipping weights.
    model.eval();maximum_error=0
    with torch.no_grad():
        reference=torch.softmax(model(torch.from_numpy(val_x[:32])),1).numpy()
    for row,expected in zip(val_x[:32],reference):
        error=float(np.max(np.abs(np.asarray(gru_predict(neural,row.tolist()))-expected)))
        maximum_error=max(maximum_error,error)
    if maximum_error>1e-6:raise ValueError("Neural export changed inference")
    neural_val_nll=neural_nll(model,val_x,val_y)
    neural_val,neural_val_scores=metrics(neural_val_nll,windows["validation"])
    baseline_threshold=float(np.quantile(baseline_val_scores,.99))
    neural_threshold=float(np.quantile(neural_val_scores,.99))
    selected="gru" if neural_val["next_event_nll_nats"]<baseline_val["next_event_nll_nats"] else "bag_centroid"
    artifacts=ROOT/"resources/models"
    write_json(artifacts/"baseline.json",baseline);write_json(artifacts/"temporal.json",neural)
    active_file="temporal.json" if selected=="gru" else "baseline.json"
    threshold=neural_threshold if selected=="gru" else baseline_threshold
    limitations=[
        "Unusual event sequences are not proof of malware; no attack labels or malware performance evaluation.",
        "Trained on a bounded2015 LANL enterprise host/network prefix; personal Windows applications may differ.",
        "Only process start/end, DNS and network destination-port categories influence scores. File, Registry and process-access evidence is excluded.",
        "LANL process names are anonymized, with no PID/parent IDs; router flow records have no process attribution. Process ancestry is displayed evidence, not learned by this model.",
        "Scores are anomaly surprise in nats, not confidence percentages or probabilities of maliciousness.",
        "Validation selected99th-percentile maximum surprise across8 targets/24-event windows. Session alerts cannot be interpreted as a calibrated false-positive rate.",
        "Mirror publisher documents official-source byte-identical acquisition; official-source full-file equality is not independently verified.",
        "Missing telemetry changes observed sequences and may change scores; low scores do not establish safety.",
        "Training aggregates host-wide events; a watched process session is a narrower stream. Network destination port53 has no training observations in this subset."]
    index={"name":"LANL temporal GRU event predictor" if selected=="gru" else "LANL bag-of-events centroid predictor",
           "version":f"lanl2015-v1-seed{args.seed}","artifact":active_file,"sha256":digest(artifacts/active_file),"threshold":threshold,
           "limitations":limitations,"training_dataset":"LANL2015 bounded proc/flows/dns prefixes, public mirror revision"+manifest["mirror_revision"],
           "selection":"Lower held-out validation next-event NLL; final test untouched until selection/threshold fixed"}
    write_json(artifacts/"active.json",index)
    # Final test is now evaluated once, after model/epoch/threshold selection.
    test_x,test_y=contexts(windows["test"])
    baseline_test,_=metrics(baseline_nll(baseline,test_x,test_y),windows["test"],baseline_threshold)
    neural_test,_=metrics(neural_nll(model,test_x,test_y),windows["test"],neural_threshold)
    baseline_val,_=metrics(baseline_val_nll,windows["validation"],baseline_threshold)
    neural_val,_=metrics(neural_val_nll,windows["validation"],neural_threshold)
    active=BehavioralModel(artifacts)
    if active.metadata["status"]!="available":raise ValueError("Exported active artifact did not load")
    times=[]
    for _ in range(30):
        t=time.perf_counter();active.predict(test_x[0].tolist());times.append((time.perf_counter()-t)*1000)
    import psutil
    rss=psutil.Process().memory_info().rss/1024/1024
    results={"configuration":vars(args),"objective":"Self-supervised next supported host-event token prediction; anomaly score maximum target NLL across8 targets",
        "selected_default":selected,"selection_basis":"validation next-event NLL only",
        "baseline":{"architecture":"8 learned histogram centroids with Laplace-smoothed next-token distribution","training_seconds":baseline_seconds,"threshold":baseline_threshold,"validation":baseline_val,"test":baseline_test},
        "temporal":{"architecture":"PyTorch GRU,8-dimension token embedding,16 hidden units","training_seconds":neural_seconds,"threshold":neural_threshold,"validation":neural_val,"test":neural_test,"epochs":history},
        "unavailable_metrics":{"precision":None,"recall":None,"f1":None,"pr_auc":None,"false_positive_rate":None,"false_alerts_per_hour":None,"detection_latency":None,
            "reason":"No attack/negative ground-truth labels or application recording denominator available. Exceedance rate counts unlabelled windows only."},
        "export_maximum_probability_error":maximum_error,"inference_one_prediction_ms":{"median":float(np.median(times)),"p95":float(np.quantile(times,.95)),"samples":len(times)},
        "training_final_rss_mib":rss,"training_peak_rss_mib":None,"artifact_bytes":{p.name:p.stat().st_size for p in artifacts.glob("*.json")},
        "hardware":{"platform":platform.platform(),"processor":platform.processor(),"cpu_logical":os.cpu_count(),"device":"CPU","torch":torch.__version__,"numpy":np.__version__,"threads":2},
        "total_seconds":time.perf_counter()-started,"dataset_manifest_sha256":digest(ROOT/"training/data/lanl-manifest.json"),"limitations":limitations}
    write_json(result_dir/"metrics.json",results)
    torch.save({"state_dict":best_state,"configuration":vars(args),"feature_schema":FEATURE_SCHEMA},result_dir/"temporal-checkpoint.pt")
    print(json.dumps({"selected":selected,"baseline_test":baseline_test,"temporal_test":neural_test,"inference":results["inference_one_prediction_ms"],"export_error":maximum_error,"total_seconds":results["total_seconds"]}),flush=True)

if __name__=="__main__":main()
