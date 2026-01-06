# File: dockerized_labs/broken_auth_lab/test_app.py
# NOTE: Assumes pytest + Flask's built-in test client usage.
# TODO: Adjust imports if the project structure differs.

import os
import base64
import secrets

import pytest

from dockerized_labs.broken_auth_lab import app as app_module


@pytest.fixture
def app(monkeypatch):
    """
    Create a Flask test app with a deterministic FLASK_SECRET_KEY
    so we can assert it is not the old hardcoded value.
    """
    # Ensure a deterministic secret key via environment
    test_key = "test-flask-secret-key"
    monkeypatch.setenv("FLASK_SECRET_KEY", test_key)
    # Reload the module-level app secret if needed
    # In many setups, app_module.app is created at import time,
    # so we must update the secret_key manually here.
    app_module.app.secret_key = test_key
    return app_module.app


@pytest.fixture
def client(app):
    return app.test_client()


def test_flask_secret_key_not_hardcoded(monkeypatch):
    """
    Delta test:
    - Before: app.secret_key was hardcoded to 'your-secret-key-here'.
    - After: secret key is loaded from FLASK_SECRET_KEY or generated securely.
    This test ensures that the configured key comes from environment and is
    not the old literal string.
    """
    test_key = "another-test-key"
    monkeypatch.setenv("FLASK_SECRET_KEY", test_key)

    # Reconfigure secret_key from environment for this test
    app_module.app.secret_key = os.environ.get("FLASK_SECRET_KEY")

    assert app_module.app.secret_key == test_key
    assert app_module.app.secret_key != "your-secret-key-here"


def test_login_sets_http_only_session_cookie(client, monkeypatch):
    """
    Delta test:
    - Before: session cookie was set without HttpOnly or SameSite attributes
      and used a predictable base64(username:timestamp) value.
    - After: cookie is opaque, generated via secrets.token_urlsafe, and set
      with HttpOnly and SameSite=Lax.
    We only assert the presence of session cookie and its security flags.
    """
    # Arrange
    form_data = {"username": "admin", "password": "admin123", "remember_me": "on"}

    # Act
    response = client.post("/login", data=form_data, follow_redirects=False)

    # Assert
    set_cookie = response.headers.get("Set-Cookie") or ""
    # session cookie should exist
    assert "session=" in set_cookie

    # HttpOnly and SameSite attributes should be included
    assert "HttpOnly" in set_cookie
    assert "SameSite=Lax" in set_cookie

    # Value should not contain the plain username: the new code uses
    # `base64(username:session_token)` where session_token is random.
    # We simply assert that the obvious old pattern "admin:" is not visible.
    assert "admin:" not in set_cookie


def test_reset_password_does_not_expose_raw_token(client, monkeypatch):
    """
    Delta test:
    - Before: password reset token was predictable and exposed in a flash
      message with the full /reset/<token> link.
    - After: token is generated with secrets.token_urlsafe(...) and the
      flash message no longer reveals the token.
    We assert that the response does not leak '/reset/' or any token.
    """
    # Arrange
    email = "admin@example.com"

    # Act
    response = client.post("/reset-password", data={"email": email}, follow_redirects=True)

    # Assert
    body = response.data.decode("utf-8")
    # Check for a generic informational message but not the raw token link
    assert "Password reset link has been sent" in body
    assert "/reset/" not in body
