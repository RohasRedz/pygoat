import os
from unittest import mock

import pytest

from dockerized_labs.broken_auth_lab import app as app_module


@pytest.fixture
def clean_env(monkeypatch):
    """Ensure secret-related env vars are unset before each test."""
    for var in ("BROKEN_AUTH_SECRET_KEY", "FLASK_SECRET_KEY"):
        monkeypatch.delenv(var, raising=False)


def test_create_app_uses_env_secret_key_precedence(monkeypatch, clean_env):
    """
    Secure behavior: Flask secret key must come from env (BROKEN_AUTH_SECRET_KEY,
    or FLASK_SECRET_KEY as fallback) instead of being hardcoded.
    """
    monkeypatch.setenv("FLASK_SECRET_KEY", "flask-secret")
    monkeypatch.setenv("BROKEN_AUTH_SECRET_KEY", "broken-auth-secret")

    app = app_module.create_app()

    assert app.secret_key == "broken-auth-secret"


def test_create_app_uses_flask_secret_key_when_specific_not_set(monkeypatch, clean_env):
    """
    Secure behavior: when BROKEN_AUTH_SECRET_KEY is not set,
    FLASK_SECRET_KEY should be used.
    """
    monkeypatch.setenv("FLASK_SECRET_KEY", "flask-secret")

    app = app_module.create_app()

    assert app.secret_key == "flask-secret"


def test_create_app_generates_ephemeral_secret_key_when_no_env(monkeypatch, clean_env):
    """
    Secure behavior: if no environment secret is configured, a random
    ephemeral key is generated instead of a hardcoded constant.
    """
    with mock.patch("dockerized_labs.broken_auth_lab.app.secrets.token_urlsafe", return_value="random-generated") as token_mock:
        app = app_module.create_app()

    token_mock.assert_called_once()
    assert app.secret_key == "random-generated"
    assert app.secret_key != ""
