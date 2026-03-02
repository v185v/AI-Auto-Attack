from backend.security.secrets_manager import SecretManager, SecretManagerSettings


def test_secret_manager_resolves_env_mapping_with_prefix(monkeypatch) -> None:
    monkeypatch.setenv("APP_SIGNING_KEY", "secret-sign-key")
    manager = SecretManager(
        SecretManagerSettings(
            provider="env",
            env_prefix="APP_",
            env_mapping={"approval_signing_key": "SIGNING_KEY"},
        )
    )

    assert manager.get("approval_signing_key") == "secret-sign-key"


def test_secret_manager_returns_default_when_provider_unsupported() -> None:
    manager = SecretManager(
        SecretManagerSettings(
            provider="vault",
            env_prefix="",
            env_mapping={},
        )
    )

    assert manager.get("approval_signing_key", default="fallback-key") == "fallback-key"
