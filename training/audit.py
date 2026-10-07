"""Analyze frozen held-out predictions without fitting/tuning anything."""
from __future__ import annotations
import json
import time
import numpy as np
import torch
from train import ROOT,prepare,contexts,baseline_nll,neural_nll,TemporalPredictor,TOKENS,write_json
from backend.model import BehavioralModel

def main():
    torch.set_num_threads(2)
    metrics=json.loads((ROOT/"training/results/metrics.json").read_text())
    args=metrics["configuration"]
    windows,_,_,_=prepare(ROOT/"training/data",args["max_train_windows"],args["max_eval_windows"],args["seed"])
    x,y=contexts(windows["test"])
    baseline=json.loads((ROOT/"resources/models/baseline.json").read_text())
    neural=json.loads((ROOT/"resources/models/temporal.json").read_text())
    model=TemporalPredictor()
    keys={"embedding":"embedding.weight","weight_ih":"gru.weight_ih_l0","weight_hh":"gru.weight_hh_l0",
          "bias_ih":"gru.bias_ih_l0","bias_hh":"gru.bias_hh_l0","output_weight":"output.weight","output_bias":"output.bias"}
    model.load_state_dict({v:torch.tensor(neural[k],dtype=torch.float32) for k,v in keys.items()})
    losses={"baseline":baseline_nll(baseline,x,y),"temporal":neural_nll(model,x,y)}
    subgroup={}
    for i,token in enumerate(TOKENS):
        mask=y==i
        subgroup[token]={"target_count":int(mask.sum()),
            "baseline_mean_nll_nats":float(losses["baseline"][mask].mean()) if mask.any() else None,
            "temporal_mean_nll_nats":float(losses["temporal"][mask].mean()) if mask.any() else None}
    # Check the frozen audit reproduces saved aggregate evaluation.
    for key,nll in losses.items():
        if abs(float(nll.mean())-metrics[key]["test"]["next_event_nll_nats"])>1e-7:
            raise ValueError("Frozen evaluation aggregate changed")
    metrics["held_out_target_subgroups"]=subgroup
    active=BehavioralModel(ROOT/"resources/models")
    events=[{"id":str(i),"timestamp":f"2026-10-07T00:00:{i:02d}Z","kind":"network","details":{"destination_port":443}} for i in range(24)]
    timings=[]
    for _ in range(50):
        started=time.perf_counter();active.score(events);timings.append((time.perf_counter()-started)*1000)
    metrics["inference_complete_score_call_ms"]={"median":float(np.median(timings)),"p95":float(np.quantile(timings,.95)),"samples":50,
                                               "workload":"24 explicitly fabricated input events,8 predictions; timing only, no accuracy claim"}
    write_json(ROOT/"training/results/metrics.json",metrics)
    np.savez_compressed(ROOT/"training/results/frozen-test-predictions.npz",target_tokens=y,baseline_nll=losses["baseline"],temporal_nll=losses["temporal"])
    print(json.dumps({"subgroups":subgroup,"complete_score_latency":metrics["inference_complete_score_call_ms"]}),flush=True)

if __name__=="__main__":main()
