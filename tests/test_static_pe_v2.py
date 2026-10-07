"""Feature-label separation and temporal selection for the independent PE experiment."""
import copy
import hashlib
import io
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
