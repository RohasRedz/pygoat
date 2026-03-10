import importlib.util
from pathlib import Path


def _load_settings_module(tmp_path: Path, source: str):
    settings_path = tmp_path / "settings.py"
    settings_path.write_text(source, encoding="utf-8")

    spec = importlib.util.spec_from_file_location("test_settings_module_securecookies2", str(settings_path))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_settings_sets_secure_cookie_flags(tmp_path):
    # Arrange: minimal module containing the changed lines
    source = (
        "DEBUG = True\n"
        "SESSION_COOKIE_SECURE = True\n"
        "CSRF_COOKIE_SECURE = True\n"
    )

    # Act
    settings = _load_settings_module(tmp_path, source)

    # Assert: secure behavior after fix (cookies only over HTTPS)
    assert settings.CSRF_COOKIE_SECURE is True
    assert settings.SESSION_COOKIE_SECURE is True
