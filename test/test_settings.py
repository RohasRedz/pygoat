# test/test_settings.py
import importlib.util
import sys
from pathlib import Path


def _load_settings_module_from_repo_root():
    # Assumption: tests run from repo root; settings.py exists at the patched path.
    settings_path = (
        Path.cwd()
        / "dockerized_labs"
        / "sensitive_data_exposure"
        / "sensitive_data_lab"
        / "settings.py"
    )
    spec = importlib.util.spec_from_file_location("sensitive_data_lab_settings", settings_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_settings_enforces_secure_cookie_and_https_redirect_flags():
    settings = _load_settings_module_from_repo_root()

    assert getattr(settings, "CSRF_COOKIE_SECURE") is True
    assert getattr(settings, "SESSION_COOKIE_SECURE") is True
    assert getattr(settings, "SECURE_SSL_REDIRECT") is True


def test_settings_disables_debug_and_enforces_session_cookie_secure():
    settings = _load_settings_module_from_repo_root()

    assert getattr(settings, "DEBUG") is False
    assert getattr(settings, "SESSION_COOKIE_SECURE") is True
