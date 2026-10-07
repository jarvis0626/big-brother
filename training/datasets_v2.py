"""Acquire and normalize inert, pinned public Windows telemetry recordings.

No downloaded command or executable is run. OTRF labels describe lab scenarios,
not individual malicious events. All caches and normalized recordings stay on D:.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "training" / "data" / "v2"
CATALOG = ROOT / "training" / "catalog-v2.json"
GUID = re.compile(r"^\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?$", re.I)
KINDS = {1:"process_start", 3:"network", 5:"process_end", 7:"image_load",
         8:"remote_thread", 10:"process_access", 11:"file_create", 12:"registry",
         13:"registry", 14:"registry", 22:"dns", 23:"file_delete", 26:"file_delete"}
SCENARIO_LABEL = "Recorded adversary emulation; mixed background; no event-level labels"

def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda:stream.read(2**20), b""): digest.update(block)
    return digest.hexdigest()

def check_hash(path, expected):
    if sha256(path) != expected: raise ValueError(f"Dataset checksum mismatch: {Path(path).name}")

def _safe_member(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
        raise ValueError("Unsafe archive member path")
    return path

def acquire(catalog):
    """Download only official revision archives and extract enumerated data files."""
    DATA.mkdir(parents=True,exist_ok=True)
    usage = shutil.disk_usage(DATA.parent)
    maximum_download = sum(source["archive_bytes"] for source in catalog["acquired_sources"])
    if usage.free - maximum_download*8 < usage.total*.20:
        raise ValueError("Download would violate the 20% free-space reserve")
    for source in catalog["acquired_sources"]:
        base = DATA/source["id"]; base.mkdir(parents=True,exist_ok=True)
        archive = base/"repository.zip"
        if not archive.exists():
            partial = base/"repository.part"
            request = urllib.request.Request(source["archive_url"],headers={"User-Agent":"Big-Brother-dataset-acquisition"})
            with urllib.request.urlopen(request,timeout=45) as response, partial.open("wb") as output:
                total = 0
                while block := response.read(2**20):
                    total += len(block)
                    if total > source["archive_bytes"]: raise ValueError("Archive exceeded pinned size")
                    output.write(block)
            check_hash(partial,source["archive_sha256"])
            partial.replace(archive)
        check_hash(archive,source["archive_sha256"])
        entries = {entry["path"]:entry for entry in source["files"]}
        with zipfile.ZipFile(archive) as container:
            for member in container.infolist():
                if member.is_dir(): continue
                path = _safe_member(member.filename)
                relative = PurePosixPath(*path.parts[1:]); entry = entries.get(str(relative))
                if not entry: continue
                if member.file_size != entry["bytes"]: raise ValueError("Pinned member size mismatch")
                target = base/relative; target.parent.mkdir(parents=True,exist_ok=True)
                if not target.exists():
                    with container.open(member) as incoming,target.open("wb") as output:
                        shutil.copyfileobj(incoming,output)
                check_hash(target,entry["sha256"])
        print(f"Verified {source['id']}: {len(entries)} inert data and metadata files",flush=True)

def metadata_index(base):
    """Read known scalar fields as text; never interpret YAML tags or scripts."""
    result = {}
    for path in sorted((base/"datasets").glob("*/_metadata/*.yaml")):
        text = path.read_text(encoding="utf-8-sig")
        def scalar(key):
            match = re.search(r"^"+key+r":\s*(.*?)\s*$",text,re.M)
            return match.group(1).strip("\"'") if match else ""
        item = {"id":scalar("id"),"title":scalar("title"),
                "metadata_path":path.relative_to(base).as_posix(),
                "techniques":sorted(set(re.findall(r"\bT[0-9]{4}\b",text)))}
        for link in re.findall(r"https://raw\.githubusercontent\.com/OTRF/Security-Datasets/[^\s]+",text):
            marker = "/datasets/"
            if marker in link:
                result.setdefault("datasets/"+link.split(marker,1)[1].rstrip("'\""),[]).append(item)
    return result

def process_key(scope, host, value):
    match = GUID.fullmatch(str(value or ""))
    if not match or match.group(1) == "00000000-0000-0000-0000-000000000000": return None
    host_hash = hashlib.sha256(str(host).lower().encode()).hexdigest()[:10]
    return f"recording:{scope}:{host_hash}:{match.group(1).lower()}"

def normalize_record(record, scope, source_record_id):
    if record.get("Channel") != "Microsoft-Windows-Sysmon/Operational": return None,"other_channel"
    try: event_id = int(record.get("EventID",0))
    except (ValueError,TypeError): return None,"malformed_event_id"
    if event_id not in KINDS: return None,"unsupported_event_id"
    source_event = event_id in {8,10}
    key = process_key(scope,record.get("Hostname",record.get("Computer","unknown")),
                      record.get("SourceProcessGUID",record.get("SourceProcessGuid")) if source_event
                      else record.get("ProcessGuid",record.get("ProcessGUID")))
    if not key: return None,"missing_process_guid"
    try:
        value = record.get("UtcTime")
        if not value: return None,"missing_utc_timestamp"
        stamp = datetime.fromisoformat(str(value).replace("Z","+00:00"))
        if stamp.tzinfo is None: stamp = stamp.replace(tzinfo=timezone.utc)
        stamp = stamp.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
        pid = int(record.get("SourceProcessId" if source_event else "ProcessId",0))
        if not 0 <= pid <= 2**32-1: raise ValueError("PID")
    except (ValueError,TypeError,OverflowError): return None,"malformed_identity_or_time"
    details = {"sysmon_event_id":event_id,"host":str(record.get("Hostname",record.get("Computer","unknown")))[:255]}
    mapping = {"DestinationIp":"destination_ip","DestinationPort":"destination_port","SourceIp":"source_ip",
               "SourcePort":"source_port","Protocol":"protocol","Initiated":"initiated","TargetFilename":"target",
               "TargetObject":"target","Details":"Details","EventType":"EventType","QueryName":"query",
               "QueryStatus":"query_status","QueryResults":"query_results","ImageLoaded":"image_loaded",
               "GrantedAccess":"granted_access","TargetImage":"target_image","CallTrace":"call_trace",
               "StartAddress":"start_address","StartModule":"start_module","StartFunction":"start_function"}
    for original,normalized in mapping.items():
        if original in record: details[normalized] = str(record[original])[:8192]
    for port in ["destination_port","source_port"]:
        if port in details:
            try:
                value = int(details[port]); details[port] = value if 0 <= value <= 65535 else None
            except (ValueError,TypeError): details[port] = None
    if source_event:
        target_key = process_key(scope,details["host"],record.get("TargetProcessGUID",record.get("TargetProcessGuid")))
        if target_key: details["target_process_key"] = target_key
    event = {"process_key":key,"pid":pid,"timestamp":stamp,"kind":KINDS[event_id],
             "image":str(record.get("SourceImage" if source_event else "Image",""))[:4096],
             "command_line":str(record.get("CommandLine",""))[:8192],"details":details,
             "source":f"recording:{scope}","source_record_id":str(source_record_id),"uncertain":event_id!=1}
    if event_id == 1:
        parent = process_key(scope,details["host"],record.get("ParentProcessGuid",record.get("ParentProcessGUID")))
        if parent: event["parent_key"] = parent
        for original,normalized in [("ParentImage","parent_image"),("ParentCommandLine","parent_command_line")]:
            if original in record:details[normalized] = str(record[original])[:8192]
    return event,None

def read_otrf(path):
    """Stream bounded NDJSON; archive contents stay inert and are not extracted."""
    count = 0; expanded = 0
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            _safe_member(member.filename)
            if member.is_dir():continue
            if not member.filename.lower().endswith(".json"): raise ValueError("Non-JSON member in host-log archive")
            expanded += member.file_size
            if expanded > 2*1024**3: raise ValueError("Expanded host-log ceiling exceeded")
            member_id = hashlib.sha256(member.filename.encode()).hexdigest()[:12]
            with archive.open(member) as stream:
                for line_number,line in enumerate(iter(lambda:stream.readline(1024*1024+1),b""),1):
                    if len(line)>1024*1024:raise ValueError("Oversized log record")
                    if not line.strip(): continue
                    count += 1
                    if count > 1_000_000:raise ValueError("Host-log record ceiling exceeded")
                    value = json.loads(line.decode("utf-8-sig"))
                    if not isinstance(value,dict):raise ValueError("Host-log record must be an object")
                    yield value,f"{member_id}:{line_number}"

def read_evtx(path):
    """Use Windows' read-only offline event parser; no log replay or import."""
    if os.name != "nt":raise ValueError("Native EVTX parsing requires Windows")
    if Path(path).stat().st_size>32*1024**2:raise ValueError("EVTX size ceiling exceeded")
    completed = subprocess.run(["wevtutil.exe","qe",str(Path(path).resolve()),"/lf:true","/f:xml","/e:Events","/uni:true","/c:100001"],
                               capture_output=True,timeout=30,check=True)
    if len(completed.stdout)>64*1024**2:raise ValueError("EVTX XML size ceiling exceeded")
    payload = completed.stdout.decode("utf-16" if completed.stdout.startswith((b"\xff\xfe",b"\xfe\xff")) else "utf-8")
    if "<!DOCTYPE" in payload.upper() or "<!ENTITY" in payload.upper():raise ValueError("XML entities prohibited")
    root = ET.fromstring(payload)
    for number,node in enumerate(root,1):
        if number>100000:raise ValueError("EVTX record ceiling exceeded")
        def find(tag):
            item = node.find("{*}System/{*}"+tag)
            return item.text if item is not None else ""
        values = {item.attrib.get("Name"):item.text or "" for item in node.findall("{*}EventData/{*}Data")}
        values.update({"EventID":find("EventID"),"Hostname":find("Computer"),"Channel":find("Channel")})
        yield values,str(find("EventRecordID") or number)

def build_recording(source, entry, records, metadata):
    counts = Counter(); events = []; seen = set(); scope = entry["sha256"][:16]
    for record,record_id in records:
        counts["raw_records"] += 1
        event,reason = normalize_record(record,scope,record_id)
        if event is None:counts[reason] += 1;continue
        identity = json.dumps([event["process_key"],event["timestamp"],event["kind"],event["image"],event["command_line"],event["details"]],sort_keys=True)
        if identity in seen:counts["duplicate_records"] += 1;continue
        seen.add(identity);events.append(event)
    events.sort(key=lambda e:(e["timestamp"],e["source_record_id"]))
    keys = {event["process_key"] for event in events}
    starts = {event["process_key"] for event in events if event["kind"]=="process_start"}
    parent_keys = {event["parent_key"] for event in events if event.get("parent_key")}
    for event in events: event["uncertain"] = event["process_key"] not in starts
    coverage = {"label_scope":"scenario","missing_process_start_count":len(keys-starts),
                "missing_parent_count":len(parent_keys-keys),"normalized_events":len(events),
                "raw_record_counts":dict(counts),"event_kind_counts":dict(Counter(e["kind"] for e in events)),
                "notes":["Partial scenario captures include background events; no event-level attack labels.",
                         "Observed process GUIDs retain identity; missing creation or parent events are not invented.",
                         "The shipped model scores only process, DNS and port-category network events."]}
    path = entry["path"]
    provenance = {"dataset":source["name"],"revision":source["revision"],"sha256":entry["sha256"],
                  "source_url":source["raw_url_prefix"]+urllib.parse.quote(path),
                  "scenario_level_label":SCENARIO_LABEL,"license":source["license"],
                  "license_url":source["license_url"],"metadata_sources":metadata,"raw_archive_path":path,
                  "event_labels_available":False,"collection":"Recorded laboratory adversary activity; background mixed"}
    return {"format":"big-brother-recording-v1","fabricated":False,
            "name":metadata[0]["title"] if metadata else Path(path).stem.replace("_"," "),
            "provenance":provenance,"coverage":coverage,"events":events}

def iter_scenarios(data_dir=DATA):
    index = json.loads((Path(data_dir)/"recordings"/"index.json").read_text(encoding="utf-8"))
    for entry in index["scenarios"]:
        path = Path(data_dir)/"recordings"/entry["filename"]
        check_hash(path,entry["normalized_sha256"])
        yield json.loads(path.read_text(encoding="utf-8"))

def normalize(catalog, output_dir=None):
    output = Path(output_dir or DATA/"recordings");output.mkdir(parents=True,exist_ok=True)
    index = {"schema_version":1,"label_scope":"scenario","scenarios":[],"excluded":[],"sources":[]}
    for source in catalog["acquired_sources"]:
        base = DATA/source["id"]; metadata = metadata_index(base) if source["id"]=="otrf" else {}
        if not base.is_dir():raise ValueError(f"Dataset cache missing: run --acquire first ({source['id']})")
        index["sources"].append({k:source[k] for k in ["id","revision","license","archive_sha256"]})
        seen_archives = set()
        for entry in source["files"]:
            suffix = ".zip" if source["id"]=="otrf" else ".evtx"
            if not entry["path"].endswith(suffix):continue
            if source["id"]=="evtx" and "sysmon" not in entry["path"].lower():continue
            if entry["sha256"] in seen_archives:
                index["excluded"].append({"source":source["id"],"path":entry["path"],"reason":"Byte-identical raw archive already included; not an independent scenario"});continue
            seen_archives.add(entry["sha256"])
            path = base/entry["path"]
            try:
                check_hash(path,entry["sha256"])
                records = read_otrf(path) if source["id"]=="otrf" else read_evtx(path)
                recording = build_recording(source,entry,records,metadata.get(entry["path"],[]))
                if not recording["events"]:
                    index["excluded"].append({"source":source["id"],"path":entry["path"],"reason":"No supported GUID-identified Windows Sysmon events","counts":recording["coverage"]["raw_record_counts"]});continue
                filename = source["id"]+"-"+entry["sha256"][:16]+".json"
                target = output/filename
                target.write_text(json.dumps(recording,ensure_ascii=False,separators=(",",":")),encoding="utf-8")
                index["scenarios"].append({"filename":filename,"source":source["id"],"name":recording["name"],
                                          "raw_archive_path":entry["path"],"normalized_sha256":sha256(target),
                                          "bytes":target.stat().st_size,"coverage":recording["coverage"]})
                print(source["id"],Path(entry["path"]).name,len(recording["events"]),flush=True)
            except (OSError,ValueError,zipfile.BadZipFile,json.JSONDecodeError,subprocess.SubprocessError,ET.ParseError) as error:
                index["excluded"].append({"source":source["id"],"path":entry["path"],"reason":type(error).__name__+": "+str(error)[:300]})
    if not index["scenarios"]:raise ValueError("No usable recording scenarios; review excluded source records")
    (output/"index.json").write_text(json.dumps(index,indent=2),encoding="utf-8")
    print("Normalized",len(index["scenarios"]),"scenarios; excluded",len(index["excluded"]),flush=True)
    return index

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acquire",action="store_true");parser.add_argument("--normalize",action="store_true")
    args=parser.parse_args();catalog=json.loads(CATALOG.read_text(encoding="utf-8"))
    if args.acquire:acquire(catalog)
    if args.normalize:normalize(catalog)
    if not (args.acquire or args.normalize):parser.print_help()
