# File: dockerized_labs/sensitive_data_exposure/sensitive_data_lab/test_settings.py
# NOTE: Assumes pytest and direct import of the Django settings module.
# These tests only validate SECRET_KEY sourcing behavior and do not require Django setup.
# TODO: If Django settings are auto-configured elsewhere, adjust import path accordingly.

import importlib
import os
import sys

import pytest


@pytest.fixture
def reload_settings(monkeypatch):
    """
    Helper to reload the settings module with a clean import so changes
    to environment variables take effect for each test.
    """

    def _reload():
        module_name = "dockerized_labs.sensitive_data_exposure.sensitive_data_lab.settings"
        if module_name in sys.modules:
            del sys.modules[module_name]
        return importlib.import_module(module_name)

    return _reload


def test_secret_key_uses_environment_variable(monkeypatch, reload_settings):
    """
    Delta test:
    - Before: SECRET_KEY was a single hardcoded string value.
    - After: SECRET_KEY is loaded from DJANGO_SECRET_KEY environment variable
      with a demo default fallback.
    This test ensures that when DJANGO_SECRET_KEY is set, it is used as-is.
    """
    env_key = "test-django-secret-key"
    monkeypatch.setenv("DJANGO_SECRET_KEY", env_key)

    settings = reload_settings()
    assert settings.SECRET_KEY == env_key


def test_secret_key_not_equal_to_old_literal(monkeypatch, reload_settings):
    """
    Delta test:
    Ensure that SECRET_KEY no longer equals the previous hardcoded value
    'django-insecure-key-for-demonstration-only' when an environment
    override is provided.
    """
    old_literal = "django-insecure-key-for-demonstration-only"
    monkeypatch.setenv("DJANGO_SECRET_KEY", "some-other-key")

    settings = reload_settings()
    assert settings.SECRET_KEY != old_literal
