import importlib.util
import pathlib


def _load_module_from_path(module_name: str, file_path: str):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_settings_enforces_secure_session_cookie_flag():
    # Arrange
    settings_path = pathlib.Path("dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py")
    assert settings_path.exists(), "settings.py must exist at the expected path for this unit test"

    # Act
    settings = _load_module_from_path("sensitive_data_lab_settings", str(settings_path))

    # Assert
    assert getattr(settings, "SESSION_COOKIE_SECURE") is True
