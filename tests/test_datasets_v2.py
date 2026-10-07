"""Meaningful parser/provenance boundaries for data-only external recordings."""
import copy
import hashlib
import json
from pathlib import Path
import types
import zipfile
import pytest
from training import datasets_v2 as dataset

GUID_A = "{365abb72-2b1b-5cd8-0000-0010ccc92500}"
GUID_B = "{365abb72-2b21-5cd8-0000-001039dd2500}"

def record(event_id=1, **changes):
    result={"Channel":"Microsoft-Windows-Sysmon/Operational","EventID":event_id,
            "UtcTime":"2019-05-12 14:18:03.558","Hostname":"lab","ProcessGuid":GUID_A,
            "ProcessId":"3320","Image":"C:\\Windows\\cmd.exe","CommandLine":"inert observed text"}
    result.update(changes);return result

def source():
    return {"name":"Test recording corpus","revision":"0"*40,"raw_url_prefix":"https://example.test/commit/",
            "license":"MIT","license_url":"https://example.test/LICENSE"}

def test_identity_is_guid_host_and_capture_scoped():
    one,_=dataset.normalize_record(record(),"a"*16,"1")
    other,_=dataset.normalize_record(record(Hostname="other"),"a"*16,"1")
    capture,_=dataset.normalize_record(record(),"b"*16,"1")
    assert len({one["process_key"],other["process_key"],capture["process_key"]})==3
    assert one["timestamp"]=="2019-05-12T14:18:03.558000Z"
    assert one["source"].startswith("recording:")
    assert one["command_line"]=="inert observed text"

def test_missing_guid_or_timestamp_never_invents_process_identity():
    assert dataset.normalize_record(record(ProcessGuid=""),"a","1")[1]=="missing_process_guid"
    assert dataset.normalize_record(record(UtcTime="",TimeCreated="2019-05-12 06:18:03"),"a","1")[1]=="missing_utc_timestamp"
    assert dataset.normalize_record(record(ProcessGuid="{00000000-0000-0000-0000-000000000000}"),"a","1")[0] is None

def test_source_target_relationship_and_ports_survive():
    event,_=dataset.normalize_record(record(10,SourceProcessGUID=GUID_A,SourceProcessId="3",
                   SourceImage="source.exe",TargetProcessGUID=GUID_B,TargetImage="target.exe",GrantedAccess="0x1000"),"a","1")
    assert event["kind"]=="process_access" and event["image"]=="source.exe"
    assert event["details"]["target_process_key"].endswith(GUID_B.strip("{}").lower())
    network,_=dataset.normalize_record(record(3,DestinationPort="3389",DestinationIp="127.0.0.1"),"a","2")
    assert network["kind"]=="network" and network["details"]["destination_port"]==3389

def test_labels_never_enter_events_and_missing_ancestry_is_measured():
    records=[(record(ParentProcessGuid=GUID_B),"1"),(record(3,ProcessGuid=GUID_B),"2"),(record(Channel="Security"),"3")]
    data=dataset.build_recording(source(),{"path":"case.zip","sha256":"a"*64},records,[{"title":"lab case"}])
    assert data["fabricated"] is False and data["provenance"]["event_labels_available"] is False
    assert data["coverage"]["missing_process_start_count"]==1
    assert data["coverage"]["missing_parent_count"]==0
    assert data["coverage"]["raw_record_counts"]["other_channel"]==1
    assert data["events"][0]["parent_key"]==data["events"][1]["process_key"]
    assert all("label" not in str(event).lower() for event in data["events"])
    assert [event["uncertain"] for event in data["events"]]==[False,True]

def test_same_guid_timestamp_but_distinct_command_is_not_a_duplicate():
    data=dataset.build_recording(source(),{"path":"case.zip","sha256":"a"*64},
          [(record(),"1"),(record(),"2"),(record(CommandLine="different inert text"),"3")],[])
    assert len(data["events"])==2 and data["coverage"]["raw_record_counts"]["duplicate_records"]==1

def test_archive_traversal_and_nondata_members_are_rejected(tmp_path):
    # ZipInfo normalizes OS backslashes while reading, before our parser sees them.
    with pytest.raises(ValueError,match="Unsafe"):dataset._safe_member("nested\\bad.json")
    for filename in ["../bad.json","C:/bad.json"]:
        path=tmp_path/"unsafe.zip"
        info=zipfile.ZipInfo("placeholder.json");info.filename=filename
        with zipfile.ZipFile(path,"w") as archive:archive.writestr(info,json.dumps(record()))
        with pytest.raises(ValueError,match="Unsafe"):list(dataset.read_otrf(path))
    path=tmp_path/"scripts.zip"
    with zipfile.ZipFile(path,"w") as archive:archive.writestr("script.ps1","inert text")
    with pytest.raises(ValueError,match="Non-JSON"):list(dataset.read_otrf(path))

def test_checksum_and_schema_preserved_for_ndjson(tmp_path):
    path=tmp_path/"case.zip"
    with zipfile.ZipFile(path,"w") as archive:archive.writestr("case.json",json.dumps(record())+"\n"+json.dumps(record(3)))
    rows=list(dataset.read_otrf(path));assert len(rows)==2 and rows[0][1].endswith(":1")
    dataset.check_hash(path,hashlib.sha256(path.read_bytes()).hexdigest())
    with pytest.raises(ValueError,match="checksum"):dataset.check_hash(path,"0"*64)

@pytest.mark.skipif(dataset.os.name!="nt",reason="Native Windows parser")
def test_evtx_calls_readonly_query_and_refuses_xml_entities(tmp_path,monkeypatch):
    path=tmp_path/"case.evtx";path.write_bytes(b"non-executable-test")
    calls=[]
    def fake(command,**options):
        calls.append(command)
        return types.SimpleNamespace(stdout=b'<Events><Event><System><EventID>1</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>lab</Computer><EventRecordID>7</EventRecordID></System><EventData><Data Name="ProcessGuid">'+GUID_A.encode()+b'</Data></EventData></Event></Events>')
    monkeypatch.setattr(dataset.subprocess,"run",fake)
    rows=list(dataset.read_evtx(path));assert rows[0][0]["EventID"]=="1"
    assert calls[0][1]=="qe" and "/lf:true" in calls[0] and "/f:xml" in calls[0]
    assert "/uni:true" in calls[0]
    monkeypatch.setattr(dataset.subprocess,"run",lambda *args,**kwargs:types.SimpleNamespace(stdout=b'<!DOCTYPE foo [<!ENTITY x "bad">]><Events/>'))
    with pytest.raises(ValueError,match="entities"):list(dataset.read_evtx(path))
