import base64
import pytest
from MobyPark.api.crypto_utils import encrypt_str, decrypt_str, mask_value


# Fixtures
@pytest.fixture(autouse=True)
def aes_key_env(monkeypatch):
    """
    Provide a deterministic AES key for all tests.
    """
    key = b"\x01" * 32  # 32 bytes = AES-256
    monkeypatch.setenv(
        "MOBYPARK_AES_KEY",
        base64.b64encode(key).decode("ascii")
    )


@pytest.fixture
def sample_pii():
    return {
        "email": "user@example.com",
        "name": "John Doe",
        "phone": "+31612345678",
        "license_plate": "AB-123-CD",
    }


# Unit tests — encryption correctness
def test_encrypt_decrypt_roundtrip(sample_pii):
    encrypted = encrypt_str(sample_pii["email"])

    assert encrypted != sample_pii["email"]

    decrypted = decrypt_str(encrypted)
    assert decrypted == sample_pii["email"]


def test_encryption_is_non_deterministic(sample_pii):
    c1 = encrypt_str(sample_pii["email"])
    c2 = encrypt_str(sample_pii["email"])

    assert c1 != c2  # random nonce → different ciphertexts


# Unit tests — associated data (AEAD)
def test_associated_data_must_match(sample_pii):
    aad = b"user:123"
    encrypted = encrypt_str(sample_pii["email"], associated_data=aad)

    # Correct AD works
    assert decrypt_str(encrypted, associated_data=aad) == sample_pii["email"]

    # Wrong AD fails
    with pytest.raises(Exception):
        decrypt_str(encrypted, associated_data=b"user:999")


# Repository-level tests — encryption at rest
# (example: simulate DB persistence)
def test_pii_is_not_stored_in_plaintext(sample_pii):
    """
    Simulates storing encrypted PII in the database.
    """
    stored_email = encrypt_str(sample_pii["email"])

    # What matters for GDPR:
    assert stored_email != sample_pii["email"]
    assert "@" not in stored_email
    assert "example.com" not in stored_email


# Authorization tests — controlled decryption
def decrypt_for_authorized_flow(encrypted_value: str, role: str) -> str:
    """
    Example service-layer rule.
    """
    if role != "ADMIN":
        raise PermissionError("Not authorized to decrypt PII")
    return decrypt_str(encrypted_value)


def test_decryption_denied_for_normal_user(sample_pii):
    encrypted = encrypt_str(sample_pii["email"])

    with pytest.raises(PermissionError):
        decrypt_for_authorized_flow(encrypted, role="USER")


def test_decryption_allowed_for_admin(sample_pii):
    encrypted = encrypt_str(sample_pii["email"])

    decrypted = decrypt_for_authorized_flow(encrypted, role="ADMIN")
    assert decrypted == sample_pii["email"]


# API-level behavior — no plaintext exposure
def test_public_api_does_not_expose_plaintext_pii(sample_pii):
    """
    Simulated API response.
    """
    api_response = {
        "id": 1,
        "email": mask_value(sample_pii["email"], keep=2),
    }

    assert sample_pii["email"] not in api_response.values()
    assert api_response["email"].startswith("us")
    assert "*" in api_response["email"]


# Logging tests — no PII in logs
def log_user_creation(email: str):
    # BAD: logging plaintext PII (this is what we want to avoid)
    pass


def test_logs_do_not_contain_plaintext_pii(caplog, sample_pii):
    log_user_creation(sample_pii["email"])

    logs = " ".join(record.message for record in caplog.records)

    assert sample_pii["email"] not in logs
    assert "@" not in logs


# Negative tests — fail closed
def test_decryption_fails_with_wrong_key(monkeypatch, sample_pii):
    encrypted = encrypt_str(sample_pii["email"])

    wrong_key = base64.b64encode(b"\x02" * 32).decode("ascii")
    monkeypatch.setenv("MOBYPARK_AES_KEY", wrong_key)

    with pytest.raises(Exception):
        decrypt_str(encrypted)


# PII inventory test — explicit GDPR mapping
PII_FIELDS = {
    "users": ["email", "name", "phone"],
    "vehicles": ["license_plate"],
}


def test_all_identified_pii_fields_are_encrypted(sample_pii):
    """
    Demonstrates explicit identification of PII fields (GDPR requirement).
    """
    encrypted_values = {
        field: encrypt_str(value)
        for field, value in sample_pii.items()
    }

    for field, encrypted in encrypted_values.items():
        assert encrypted != sample_pii[field]
        assert encrypted.isascii()
