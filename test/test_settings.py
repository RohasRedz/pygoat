import importlib.util
from pathlib import Path


def _load_settings_module(settings_path: Path):
    spec = importlib.util.spec_from_file_location("sensitive_data_lab_settings_under_test", str(settings_path))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_settings_enforces_secure_session_cookie():
    # Arrange
    settings_path = (
        Path(__file__).resolve().parents[1]
        / "dockerized_labs"
        / "sensitive_data_exposure"
        / "sensitive_data_lab"
        / "settings.py"
    )

    # Act
    settings = _load_settings_module(settings_path)

    # Assert
    # Regression for vulnerability fix: session cookie must be marked secure (HTTPS-only).
    assert getattr(settings, "SESSION_COOKIE_SECURE") is True
