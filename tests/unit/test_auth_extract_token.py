from MobyPark.api.authentication import extract_bearer_token


def test_happy_bearer():
    assert extract_bearer_token("Bearer abc123") == "abc123"

def test_missing_header():
    assert extract_bearer_token(None) is None

def test_wrong_scheme():
    assert extract_bearer_token("Basic abc") is None

def test_bad_format():
    assert extract_bearer_token("Bearer") is None

def test_scheme_case_insensitive():
    assert extract_bearer_token("bEaReR tok") == "tok"

def test_extra_whitespace_ok():
    assert extract_bearer_token("  Bearer   abc123   ") == "abc123"

def test_too_many_parts_returns_none():
    assert extract_bearer_token("Bearer a b") is None

def test_empty_string_returns_none():
    assert extract_bearer_token("") is None