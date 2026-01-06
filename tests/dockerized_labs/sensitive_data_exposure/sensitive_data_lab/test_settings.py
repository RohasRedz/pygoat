import os
from importlib import reload
from unittest import mock

import pytest
import dockerized_labs.sensitive_data_exposure.sensitive_data_lab.settings as settings_module


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure secret-related env vars are unset before each test."""
    for var in ("SENSITIVE_DATA_LAB_SECRET_KEY", "DJANGO_SECRET_KEY"):
        monkeypatch.delenv(var, raising=False)


def _reload_settings():
    reload(settings_module)
    return settings_module


def test_secret_key_uses_lab_specific_env(monkeypatch):
    """
    Secure behavior: SECRET_KEY must prefer SENSITIVE_DATA_LAB_SECRET_KEY when set.
    """
    monkeypatch.setenv("DJANGO_SECRET_KEY", "django-secret")
    monkeypatch.setenv("SENSITIVE_DATA_LAB_SECRET_KEY", "lab-specific-secret")

    mod = _reload_settings()
    assert mod.SECRET_KEY == "lab-specific-secret"


def test_secret_key_uses_django_secret_env_when_specific_not_set(monkeypatch):
    """
    Secure behavior: if SENSITIVE_DATA_LAB_SECRET_KEY is absent,
    DJANGO_SECRET_KEY should be used.
    """
    monkeypatch.setenv("DJANGO_SECRET_KEY", "django-secret")

    mod = _reload_settings()
    assert mod.SECRET_KEY == "django-secret"


def test_secret_key_fallback_is_generated_not_hardcoded(monkeypatch, clean_env):
    """
    Secure behavior: when no env secret is configured, settings must generate
    a random SECRET_KEY instead of using a hardcoded literal.
    """
    with mock.patch(
        "dockerized_labs.sensitive_data_exposure.sensitive_data_lab.settings.secrets.token_urlsafe",
        return_value="generated-secret",
    ) as token_mock:
        mod = _reload_settings()

    token_mock.assert_called_once()
    assert mod.SECRET_KEY == "generated-secret"
    assert mod.SECRET_KEY != ""
