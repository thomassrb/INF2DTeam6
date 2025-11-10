from types import SimpleNamespace
from MobyPark.api.authentication import extract_bearer_token

def make_headers(hdict):
    return SimpleNamespace(get=hdict.get, **hdict)

def test_happy_bearer():
    headers = make_headers({"Authorization": "Bearer abc123"})
    assert extract_bearer_token(headers) == "abc123"

def test_missing_header():
    headers = make_headers({})
    assert extract_bearer_token(headers) is None

def test_wrong_scheme():
    headers = make_headers({"Authorization": "Basic abc"})
    assert extract_bearer_token(headers) is None

def test_bad_format():
    headers = make_headers({"Authorization": "Bearer"})
    assert extract_bearer_token(headers) is None