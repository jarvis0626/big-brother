"""Feature-label separation and temporal selection for the independent PE experiment."""
import copy
import hashlib
import io
import tarfile
import pytest
from training import static_pe_v2 as static

def row():
    return {"general":dict.fromkeys(static.GENERAL,1),"strings":dict.fromkeys(static.STRINGS,2),
            "header":{"optional":dict.fromkeys(static.OPTIONAL,3)},"histogram":[1]*256,"byteentropy":[2]*256,
            "datadirectories":[],"section":{"sections":[{"entropy":4.,"size":10,"vsize":20,"props":["MEM_EXECUTE","MEM_WRITE"]}]},
            "label":1,"sha256":"0"*64,"appeared":"2018-01","avclass":"lab-family"}

def test_static_features_ignore_labels_time_identity_and_family():
    original=row();changed=copy.deepcopy(original)
    changed.update(label=0,sha256="a"*64,appeared="2018-12",avclass="other-family")
    assert static.project(original)==static.project(changed)
    assert len(static.project(original))==len(static.FEATURES)==564

def test_histograms_are_normalized_and_invalid_values_rejected():
    value=row();a=static.project(value);value["histogram"]=[100]*256;b=static.project(value)
    assert a==b
    value["byteentropy"][0]=float("nan")
    with pytest.raises(ValueError,match="finite"):static.project(value)
    value=row();value["histogram"]=[1]*255
    with pytest.raises(ValueError,match="256-bin"):static.project(value)

def test_official_test_never_enters_fit_or_validation():
    assert static.temporal_split("train","2018-08")=="train"
    assert static.temporal_split("train","2018-09")=="validation"
    assert static.temporal_split("train","2018-10")=="validation"
    assert static.temporal_split("test","2018-11")=="test"
    assert static.temporal_split("test","2018-01") is None
    assert static.temporal_split("train","2018-12") is None
    with pytest.raises(ValueError):static.temporal_split("train","2018-99")

def test_identity_subsample_is_deterministic_and_label_independent():
    assert static.selected("0"*64)
    assert not static.selected("00000001"+"0"*56)
    with pytest.raises(ValueError,match="SHA256"):static.selected("bad")

def test_oversized_rows_are_drained_hashed_and_keep_identity():
    identity="a"*64
    huge=(b'{"sha256":"'+identity.encode()+b'","ignored":"'+b'x'*300+b'"}\n')
    small=b'{"sha256":"'+b'b'*64+b'"}\n'
    digest=hashlib.sha256()
    assert list(static.feature_lines(io.BytesIO(huge+small),digest,max_bytes=128))==[(None,identity),(small,None)]
    assert digest.hexdigest()==hashlib.sha256(huge+small).hexdigest()
    with pytest.raises(ValueError,match="first-field"):
        list(static.feature_lines(io.BytesIO(b'{"unexpected":"'+b'x'*300+b'"}\n'),hashlib.sha256(),128))

def test_split_metadata_excludes_discarded_rows():
    months,families=static.retained_metadata([0,2],["2018-01","2018-02","2018-03"],["kept","excluded",None])
    assert dict(months)=={"2018-01":1,"2018-03":1}
    assert dict(families)=={"kept":1}

def test_archive_whitelist_rejects_binaries_links_and_traversal():
    assert static.member_role(tarfile.TarInfo("ember2018/train_features_0.jsonl"))=="train"
    assert static.member_role(tarfile.TarInfo("ember2018/test_features.jsonl"))=="test"
    assert static.member_role(tarfile.TarInfo("ember2018/ember_model_2018.txt"))=="unused_publisher_model"
    for name in ["ember2018/malware.exe","../outside.jsonl","/absolute.jsonl",r"ember2018\test_features.jsonl"]:
        with pytest.raises(ValueError):static.member_role(tarfile.TarInfo(name))
    link=tarfile.TarInfo("ember2018/test_features.jsonl");link.type=tarfile.SYMTYPE
    with pytest.raises(ValueError,match="regular"):static.member_role(link)

def test_frozen_experiment_refuses_before_reading_or_mutating(tmp_path,monkeypatch):
    data=tmp_path/"data";results=tmp_path/"results";data.mkdir();results.mkdir()
    monkeypatch.setattr(static,"DATA",data);monkeypatch.setattr(static,"RESULTS",results)
    monkeypatch.setattr(static,"acquire",lambda:pytest.fail("Frozen preparation must not acquire or read data"))
    cached=data/"test-features.npy";cached.write_bytes(b"sentinel cache")
    for marker in [results/"frozen-plan.json",results/"metrics.json",data/"frozen-experiment.json"]:
        marker.write_text("sentinel decisions")
        for action in [static.prepare,static.fit]:
            with pytest.raises(ValueError,match="frozen"):action()
        assert cached.read_bytes()==b"sentinel cache"
        assert marker.read_text()=="sentinel decisions"
        marker.unlink()
    static.assert_unfrozen()

def test_reproduction_paths_keep_caches_ignored_and_preserve_original_freeze(tmp_path,monkeypatch):
    monkeypatch.setattr(static,"ROOT",tmp_path)
    data=tmp_path/"training"/"data"/"separate";results=tmp_path/"training"/"results"/"separate"
    assert static.resolve_experiment_paths(data,results)==(data.resolve(),results.resolve())
    for wrong_data,wrong_results in [(tmp_path/"outside",results),(data,tmp_path/"outside"),(tmp_path/"training"/"data",results)]:
        with pytest.raises(ValueError,match="descendants"):static.resolve_experiment_paths(wrong_data,wrong_results)
    original=tmp_path/"training"/"data"/"original";original.mkdir(parents=True)
    marker=original/"frozen-experiment.json";marker.write_text("original freeze")
    with pytest.raises(ValueError,match="frozen"):static.assert_unfrozen(original,results)
    static.assert_unfrozen(data,results)
    assert marker.read_text()=="original freeze"
