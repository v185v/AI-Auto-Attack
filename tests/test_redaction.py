from backend.security.redaction import RedactionSettings, redact_payload, redact_text


def test_redact_payload_masks_sensitive_keys() -> None:
    settings = RedactionSettings(
        enabled=True,
        mask="***MASK***",
        sensitive_keys={"api_key", "password"},
    )
    payload = {
        "api_key": "abc123",
        "nested": {
            "password": "p@ssw0rd",
            "safe": "ok",
        },
        "items": [{"token": "tok-1"}, {"value": "clean"}],
    }

    redacted = redact_payload(payload, settings)
    assert redacted["api_key"] == "***MASK***"
    assert redacted["nested"]["password"] == "***MASK***"
    assert redacted["nested"]["safe"] == "ok"
    assert redacted["items"][0]["token"] == "***MASK***"
    assert redacted["items"][1]["value"] == "clean"


def test_redact_text_masks_common_secret_patterns() -> None:
    settings = RedactionSettings(
        enabled=True,
        mask="[REDACTED]",
        sensitive_keys=set(),
    )
    source = (
        "Authorization: Bearer super-token-value "
        "api_key=my-api-key "
        "url=https://alice:pa55@target.local/path"
    )
    redacted = redact_text(source, settings)

    assert "super-token-value" not in redacted
    assert "my-api-key" not in redacted
    assert "alice" not in redacted
    assert "pa55" not in redacted
    assert redacted.count("[REDACTED]") >= 3
