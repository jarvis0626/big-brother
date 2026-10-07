"""Separate research-only static PE classifier from official EMBER2018 features.

The dataset is MIT licensed. No binary is downloaded or executed. This independent
numeric projection does not copy the publisher's AGPL extractor implementation.
It does not modify the shipped behavioral model or claim modern extractor parity.
"""
from __future__ import annotations
import argparse
import array
from collections import Counter
from datetime import datetime,timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/"training"/"data"/"v2"/"static-ember"
RESULTS=ROOT/"training"/"results"/"static-v2"
ARCHIVE_URL="https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
ARCHIVE_BYTES=1696539273
ARCHIVE_SHA="b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812"
PUBLISHER_REVISION="d97a0b523de02f3fe5ea6089d080abacab6ee931"
GENERAL=["size","vsize","has_debug","exports","imports","has_relocations","has_resources","has_signature","has_tls","symbols"]
STRINGS=["numstrings","avlength","printables","entropy","paths","urls","registry","MZ"]
OPTIONAL=["major_image_version","minor_image_version","major_linker_version","minor_linker_version",
          "major_operating_system_version","minor_operating_system_version","major_subsystem_version",
          "minor_subsystem_version","sizeof_code","sizeof_headers","sizeof_heap_commit"]
DIRECTORIES=["EXPORT_TABLE","IMPORT_TABLE","RESOURCE_TABLE","EXCEPTION_TABLE","CERTIFICATE_TABLE",
             "BASE_RELOCATION_TABLE","DEBUG","ARCHITECTURE","GLOBAL_PTR","TLS_TABLE","LOAD_CONFIG_TABLE",
             "BOUND_IMPORT","IAT","DELAY_IMPORT_DESCRIPTOR","CLR_RUNTIME_HEADER"]
FEATURES=["general."+k for k in GENERAL]+["strings."+k for k in STRINGS]+["optional."+k for k in OPTIONAL]
FEATURES += ["byte_histogram."+str(k) for k in range(256)]+["byte_entropy_histogram."+str(k) for k in range(256)]
FEATURES += ["directory."+k+".size" for k in DIRECTORIES]
FEATURES += ["section.count","section.mean_entropy","section.max_entropy","section.total_raw_size",
             "section.total_virtual_size","section.executable_count","section.writable_count","section.executable_writable_count"]
FEATURE_SCHEMA="ember2018-independent-numeric-projection-v1"

def sha256(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda:f.read(2**20),b""):h.update(block)
    return h.hexdigest()

def acquire():
    DATA.mkdir(parents=True,exist_ok=True);usage=shutil.disk_usage(DATA)
    if usage.free-12*1024**3<usage.total*.20:raise ValueError("20% free-space reserve would be violated")
    path=DATA/"ember_dataset_2018_2.tar.bz2"
    if not path.exists():
        partial=DATA/"ember_dataset_2018_2.part"
        with urllib.request.urlopen(ARCHIVE_URL,timeout=45) as response,partial.open("wb") as output:
            count=0
            while block:=response.read(2**20):
                count+=len(block)
                if count>ARCHIVE_BYTES:raise ValueError("Archive byte ceiling exceeded")
                output.write(block)
        if count!=ARCHIVE_BYTES or sha256(partial)!=ARCHIVE_SHA:raise ValueError("Official EMBER checksum/size mismatch")
        partial.replace(path)
    if path.stat().st_size!=ARCHIVE_BYTES or sha256(path)!=ARCHIVE_SHA:raise ValueError("Cached EMBER checksum/size mismatch")
    return path

def _number(value):
    if not isinstance(value,(int,float)) or isinstance(value,bool) or not math.isfinite(value) or value<0:
        raise ValueError("Static feature must be a finite nonnegative number")
    return float(value)

def project(record):
    """Consume observed published numeric fields; labels/hash/time/family are excluded."""
    numbers=[]
    for group,keys in [(record["general"],GENERAL),(record["strings"],STRINGS),(record["header"]["optional"],OPTIONAL)]:
        numbers.extend(math.log1p(_number(group[k])) for k in keys)
    for name in ["histogram","byteentropy"]:
        values=record[name]
        if not isinstance(values,list) or len(values)!=256:raise ValueError("Invalid 256-bin feature histogram")
        values=[_number(value) for value in values];total=sum(values)
        numbers.extend(value/total if total else 0. for value in values)
    directories={item["name"]:item for item in record.get("datadirectories",[])}
    numbers.extend(math.log1p(_number(directories.get(k,{"size":0})["size"])) for k in DIRECTORIES)
    sections=record["section"]["sections"]
    entropies=[_number(item["entropy"]) for item in sections]
    raw=sum(_number(item["size"]) for item in sections);virtual=sum(_number(item["vsize"]) for item in sections)
    executable=sum("MEM_EXECUTE" in item["props"] for item in sections)
    writable=sum("MEM_WRITE" in item["props"] for item in sections)
    both=sum("MEM_EXECUTE" in item["props"] and "MEM_WRITE" in item["props"] for item in sections)
    numbers.extend([math.log1p(len(sections)),sum(entropies)/max(1,len(entropies)),max(entropies,default=0),
                    math.log1p(raw),math.log1p(virtual),math.log1p(executable),math.log1p(writable),math.log1p(both)])
    if len(numbers)!=len(FEATURES):raise ValueError("Static feature dimension mismatch")
    return array.array("f",numbers)

def temporal_split(source,appeared):
    if not re.fullmatch(r"\d{4}-\d{2}",str(appeared)):raise ValueError("Expected publisher month-resolution appearance")
    datetime.strptime(appeared,"%Y-%m")
    if source=="train":
        if appeared<="2018-08":return "train"
        if "2018-09"<=appeared<="2018-10":return "validation"
    elif source=="test" and appeared>="2018-11":return "test"
    return None

def selected(file_hash):
    if not re.fullmatch(r"[0-9a-f]{64}",str(file_hash)):raise ValueError("Invalid PE SHA256 identity")
    return int(file_hash[:8],16)%4==0

def feature_lines(stream,member_hash,max_bytes=4*1024**2):
    """Bound memory, hash every byte, and drain huge records without parsing them."""
    while prefix:=stream.readline(max_bytes+1):
        member_hash.update(prefix)
        if len(prefix)<=max_bytes:
            yield prefix,None
            continue
        # Publisher SHA is the first JSON field. Require that observed header so
        # omitted giant feature rows still participate in raw-identity exclusion.
        match=re.match(rb'^\s*\{\s*"sha256"\s*:\s*"([0-9a-f]{64})"',prefix)
        if match is None:raise ValueError("Oversized feature row has no valid first-field SHA256")
        chunk=prefix
        while not chunk.endswith(b"\n"):
            chunk=stream.readline(max_bytes+1)
            if not chunk:break
            member_hash.update(chunk)
        yield None,match.group(1).decode("ascii")

def retained_metadata(keep,month_values,family_values):
    """Report only records actually retained after cross-split exclusions."""
    months=Counter(month_values[i] for i in keep)
    families=Counter(family_values[i] for i in keep if family_values[i] is not None)
    return months,families

def prepare():
    """Stream the full checksum-verified feature archive without extracting raw JSON."""
    import numpy as np
    path=acquire();buffers={k:array.array("f") for k in ["train","validation","test"]}
    labels={k:array.array("b") for k in buffers};identities={k:[] for k in buffers};groups={k:[] for k in buffers}
    families={k:[] for k in buffers};months={k:[] for k in buffers}
    source_sha=set();feature_hashes={k:set() for k in buffers};stats=Counter();members=[]
    started=time.perf_counter()
    with tarfile.open(path,mode="r|bz2") as archive:
        for member in archive:
            name=PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or "\\" in member.name:raise ValueError("Unsafe tar member")
            if member.isdir():continue
            if not member.isfile() or not re.fullmatch(r"ember2018/(train_features_[0-9]+|test_features)\.jsonl",member.name):
                raise ValueError("Archive contains an unexpected non-feature member")
            if member.size>8*1024**3:raise ValueError("Expanded JSON member exceeds ceiling")
            source="train" if "/train_" in member.name else "test";stream=archive.extractfile(member)
            if stream is None:raise ValueError("Missing feature stream")
            member_hash=hashlib.sha256();member_records=0
            for line,oversized_identity in feature_lines(stream,member_hash):
                member_records+=1;stats["raw_records"]+=1
                if stats["raw_records"]>1_100_000:raise ValueError("Dataset record ceiling exceeded")
                if line is None:
                    stats["oversized_feature_record_excluded"]+=1
                    stats[f"oversized_{source}_feature_record_excluded"]+=1
                    if source=="train":source_sha.add(oversized_identity)
                    continue
                row=json.loads(line);label=row["label"];file_hash=row["sha256"]
                if not re.fullmatch(r"[0-9a-f]{64}",str(file_hash)):raise ValueError("Invalid raw PE SHA256 identity")
                if source=="train":
                    if file_hash in source_sha:stats["duplicate_raw_train_sha"]+=1;continue
                    source_sha.add(file_hash)
                stats[f"raw_label_{label}"]+=1
                if label not in {0,1}:stats["unlabeled_excluded"]+=1;continue
                split=temporal_split(source,row["appeared"])
                if split is None:stats["outside_temporal_selection"]+=1;continue
                if not selected(file_hash):stats["hash_subsample_excluded"]+=1;continue
                try:features=project(row)
                except (ValueError,KeyError,TypeError,OverflowError):stats["invalid_feature_record"]+=1;continue
                group=hashlib.sha256(features.tobytes()).hexdigest()
                if group in feature_hashes[split]:stats[f"duplicate_{split}_feature"]+=1;continue
                feature_hashes[split].add(group)
                if len(labels[split])>=250000:raise ValueError("Selected split count ceiling exceeded")
                buffers[split].extend(features);labels[split].append(label);identities[split].append(file_hash);groups[split].append(group)
                months[split].append(row["appeared"])
                families[split].append(str(row.get("avclass") or "unavailable")[:200] if label==1 else None)
                if stats["raw_records"]%100000==0:print("Streamed",stats["raw_records"],"records",flush=True)
            members.append({"name":member.name,"bytes":member.size,"sha256":member_hash.hexdigest(),"records":member_records})
            print("Processed",member.name,member_records,"records",flush=True)
    # Entire source training hashes are known regardless of archive member order.
    training_groups=set(groups["train"]);validation_groups=set();cache={};retained_families={}
    for split in ["train","validation","test"]:
        matrix=np.frombuffer(buffers[split],dtype=np.float32).reshape(-1,len(FEATURES));target=np.frombuffer(labels[split],dtype=np.int8)
        keep=[]
        for i,(file_hash,group) in enumerate(zip(identities[split],groups[split])):
            leak=(split=="validation" and group in training_groups) or (split=="test" and (file_hash in source_sha or group in training_groups or group in validation_groups))
            if leak:stats[f"cross_split_{split}_excluded"]+=1;continue
            keep.append(i)
        if split=="validation":validation_groups={groups[split][i] for i in keep}
        if not keep:raise ValueError("Empty static experiment split")
        matrix=matrix[keep];target=target[keep]
        if len(set(target.tolist()))!=2:raise ValueError("Static split must contain both publisher classes")
        np.save(DATA/(split+"-features.npy"),matrix);np.save(DATA/(split+"-labels.npy"),target)
        kept_months,kept_families=retained_metadata(keep,months[split],families[split]);retained_families[split]=set(kept_families)-{"unavailable"}
        cache[split]={"samples":len(keep),"class_counts":dict(Counter(map(int,target))),"month_counts":dict(kept_months),
                      "malware_family_count":len(retained_families[split]),"missing_malware_family_labels":kept_families["unavailable"],
                      "features_sha256":sha256(DATA/(split+"-features.npy")),"labels_sha256":sha256(DATA/(split+"-labels.npy")),
                      "selected_sha256_identity_digest":hashlib.sha256("\n".join(identities[split][i] for i in keep).encode()).hexdigest()}
    manifest={"dataset":"EMBER2018 feature version2","archive_url":ARCHIVE_URL,"archive_sha256":ARCHIVE_SHA,
              "archive_bytes":ARCHIVE_BYTES,"publisher_revision":PUBLISHER_REVISION,"data_license":"MIT",
              "license_url":f"https://github.com/elastic/ember/blob/{PUBLISHER_REVISION}/LICENSE.txt",
              "feature_schema":FEATURE_SCHEMA,"feature_count":len(FEATURES),"feature_names":FEATURES,
              "selection":"SHA256 first eight hex digits modulo four equals zero (25%); publisher labels 0/1 only; exact projected-feature duplicates removed",
              "splits":"Official train appeared <=2018-08 for fitting; official train 2018-09/10 for validation; official test >=2018-11 held out",
              "leakage":"All raw training file SHA identities excluded from heldout; identical selected feature vectors excluded across splits. Family grouping unavailable for benign files; malware families can overlap; near-duplicate/signer leakage not fully resolved",
              "oversized_records":"Rows exceeding 4 MiB are drained without parsing. Their observed first-field SHA256 remains included in raw identity exclusion; their unknown labels are omitted from raw_label counters",
              "statistics":dict(stats),"members":members,"splits_detail":cache,"prepare_seconds":time.perf_counter()-started,
              "family_overlap_count":len(retained_families["train"]&retained_families["test"]),
              "limitations":["Historical 2018 publisher labels, not current Windows deployment accuracy", "Independent numeric projection differs from the full official 2381-feature benchmark", "Runtime PE extractor parity with LIEF 0.9/0.10 is unverified; research-only", "Class prevalence and the temporal/hash subset are benchmark-specific; no live false alerts per hour"]}
    RESULTS.mkdir(parents=True,exist_ok=True);(RESULTS/"dataset-manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    return manifest

def evaluate(labels,prediction,threshold):
    import numpy as np
    from sklearn.metrics import average_precision_score,roc_auc_score,precision_score,recall_score,f1_score,accuracy_score,confusion_matrix,log_loss,brier_score_loss
    choices=prediction>=threshold;tn,fp,fn,tp=confusion_matrix(labels,choices,labels=[0,1]).ravel()
    return {"threshold":float(threshold),"roc_auc":float(roc_auc_score(labels,prediction)),"pr_auc_average_precision":float(average_precision_score(labels,prediction)),
            "accuracy":float(accuracy_score(labels,choices)),"precision":float(precision_score(labels,choices,zero_division=0)),"recall":float(recall_score(labels,choices,zero_division=0)),
            "f1":float(f1_score(labels,choices,zero_division=0)),"fpr":float(fp/(fp+tn)),"confusion":{"tn":int(tn),"fp":int(fp),"fn":int(fn),"tp":int(tp)},
            "log_loss":float(log_loss(labels,np.clip(prediction,1e-7,1-1e-7))),"brier_score":float(brier_score_loss(labels,prediction))}

def fit():
    os.environ["OMP_NUM_THREADS"]="2";os.environ["OPENBLAS_NUM_THREADS"]="2";os.environ["MKL_NUM_THREADS"]="2"
    import numpy as np
    import sklearn
    import lightgbm as lgb
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import SGDClassifier
    from sklearn.metrics import average_precision_score,precision_recall_curve
    from threadpoolctl import threadpool_limits
    manifest=json.loads((RESULTS/"dataset-manifest.json").read_text(encoding="utf-8"));data={}
    for split in ["train","validation","test"]:
        for suffix in ["features","labels"]:
            path=DATA/(split+"-"+suffix+".npy")
            if sha256(path)!=manifest["splits_detail"][split][suffix+"_sha256"]:raise ValueError("Static cache checksum mismatch")
        data[split]=(np.load(DATA/(split+"-features.npy"),mmap_mode="r"),np.load(DATA/(split+"-labels.npy")))
    X,y=data["train"];V,vy=data["validation"];started=time.perf_counter()
    models={};validation_predictions={};fitted={}
    with threadpool_limits(limits=2):
        models["linear_baseline"]=make_pipeline(StandardScaler(),SGDClassifier(loss="log_loss",alpha=1e-4,max_iter=30,tol=1e-3,random_state=1984))
        models["lightgbm"]=lgb.LGBMClassifier(n_estimators=300,num_leaves=31,learning_rate=.06,min_child_samples=40,
                   colsample_bytree=.9,subsample=.9,subsample_freq=1,n_jobs=2,random_state=1984,verbosity=-1,metric="average_precision")
        for name,model in models.items():
            begin=time.perf_counter()
            if name=="lightgbm":model.fit(X,y,eval_set=[(V,vy)],eval_metric="average_precision",callbacks=[lgb.early_stopping(30,first_metric_only=True,verbose=False)])
            else:model.fit(X,y)
            prediction=model.predict_proba(V)[:,1];validation_predictions[name]=prediction
            precision,recall,thresholds=precision_recall_curve(vy,prediction)
            f1=2*precision[:-1]*recall[:-1]/np.maximum(precision[:-1]+recall[:-1],1e-15)
            threshold=float(thresholds[int(np.argmax(f1))]);low_fpr=float(np.nextafter(np.quantile(prediction[vy==0],.99,method="higher"),np.inf))
            fitted[name]={"fit_seconds":time.perf_counter()-begin,"validation":evaluate(vy,prediction,threshold),
                          "validation_threshold_target1percentfpr":evaluate(vy,prediction,low_fpr),"threshold":threshold,"low_fpr_threshold":low_fpr}
            print("Fitted",name,"validationAP",average_precision_score(vy,prediction),flush=True)
        chosen=max(fitted,key=lambda name:fitted[name]["validation"]["pr_auc_average_precision"])
        # Freeze choices before any held-out prediction or metric calculation.
        frozen={"frozen_at_utc":datetime.now(timezone.utc).isoformat(),"seed":1984,"threads":2,"selection_metric":"Validation average precision",
                "chosen_model":chosen,"feature_schema":FEATURE_SCHEMA,"hyperparameters":{name:model.get_params(deep=False) if name=="lightgbm" else {"loss":"log_loss","alpha":1e-4,"max_iter":30} for name,model in models.items()},
                "validation":fitted,"extractor_parity":"Unverified; no shipped binary-scanning integration"}
        (RESULTS/"frozen-plan.json").write_text(json.dumps(frozen,indent=2),encoding="utf-8")
        models["lightgbm"].booster_.save_model(str(RESULTS/"lightgbm-model.txt"))
        baseline=models["linear_baseline"]
        np.savez_compressed(RESULTS/"linear-baseline.npz",mean=baseline[0].mean_,scale=baseline[0].scale_,coef=baseline[1].coef_,intercept=baseline[1].intercept_)
        T,ty=data["test"];tests={};predictions={}
        for name,model in models.items():
            begin=time.perf_counter();prediction=model.predict_proba(T)[:,1];predictions[name]=prediction
            tests[name]={"heldout":evaluate(ty,prediction,fitted[name]["threshold"]),"heldout_at_validation1percentfpr":evaluate(ty,prediction,fitted[name]["low_fpr_threshold"]),
                         "predict_seconds":time.perf_counter()-begin}
        np.savez_compressed(DATA/"heldout-predictions.npz",labels=ty,**predictions)
    metrics={"task":"Separate supervised static PE feature research experiment; NOT live behavioral detector accuracy",
             "chosen_model":chosen,"feature_schema":FEATURE_SCHEMA,"train_samples":len(y),"validation_samples":len(vy),"test_samples":len(ty),
             "models":tests,"fitting":fitted,"elapsed_fit_eval_seconds":time.perf_counter()-started,
             "versions":{"numpy":np.__version__,"sklearn":sklearn.__version__,"lightgbm":lgb.__version__},"threads":2,
             "model_artifact_sha256":{name:sha256(RESULTS/artifact) for name,artifact in {"lightgbm":"lightgbm-model.txt","linear_baseline":"linear-baseline.npz"}.items()},
             "dataset_manifest_sha256":sha256(RESULTS/"dataset-manifest.json"),
             "limits":manifest["limitations"]+ ["Provided class labels are publisher judgments; no new independent malware adjudication", "No family-disjoint test because reliable complete family labels are unavailable; reported overlap remains"]}
    (RESULTS/"metrics.json").write_text(json.dumps(metrics,indent=2),encoding="utf-8");print(json.dumps(metrics,indent=2),flush=True)
    return metrics

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--acquire",action="store_true");parser.add_argument("--prepare",action="store_true");parser.add_argument("--train",action="store_true")
    args=parser.parse_args()
    if args.acquire:print(acquire())
    if args.prepare:prepare()
    if args.train:fit()
    if not (args.acquire or args.prepare or args.train):parser.print_help()
