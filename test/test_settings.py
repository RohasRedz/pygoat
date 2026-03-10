import importlib.util
from pathlib import Path


def _load_settings_module():
    """
    Loads the Django settings.py as a plain Python module without requiring Django.
    This directly validates the security fix (secure cookie flags) introduced in the patch.
    """
    repo_root = Path(__file__).resolve().parents[1]
    settings_path = repo_root / "dockerized_labs" / "sensitive_data_exposure" / "sensitive_data_lab" / "settings.py"

    spec = importlib.util.spec_from_file_location("sensitive_data_lab_settings", settings_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_settings_enforces_secure_cookie_flags():
    settings = _load_settings_module()

    # Regression/security assertions: these must be explicitly True after the fix.
    assert getattr(settings, "CSRF_COOKIE_SECURE") is True
    assert getattr(settings, "SESSION_COOKIE_SECURE") is True
