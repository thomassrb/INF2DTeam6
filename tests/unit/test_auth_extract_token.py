from MobyPark.api.authentication import extract_bearer_token


def test_happy_bearer():
    assert extract_bearer_token("Bearer abc123") == "abc123"

def test_missing_header():
    assert extract_bearer_token(None) is None

def test_wrong_scheme():
    assert extract_bearer_token("Basic abc") is None

def test_bad_format():
    assert extract_bearer_token("Bearer") is None