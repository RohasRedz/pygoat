import importlib.util
import sys
from pathlib import Path


def _import_settings_module_from_source(tmp_path: Path, source: str):
    settings_path = tmp_path / "settings.py"
    settings_path.write_text(source, encoding="utf-8")

    spec = importlib.util.spec_from_file_location("tmp_settings", str(settings_path))
    module = importlib.util.module_from_spec(spec)
    sys.modules["tmp_settings"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_settings_does_not_set_secure_cookie_flags_when_debug_true(tmp_path):
    # Arrange: settings.py as patched, with DEBUG=True and secure flags gated by `if not DEBUG:`
    patched_source = (
        "DEBUG = True\n"
        "\n"
        "if not DEBUG:\n"
        "    CSRF_COOKIE_SECURE = True\n"
        "    SESSION_COOKIE_SECURE = True\n"
    )

    # Act
    settings = _import_settings_module_from_source(tmp_path, patched_source)

    # Assert: secure flags should not exist when DEBUG=True (gated off)
    assert settings.DEBUG is True
    assert not hasattr(settings, "CSRF_COOKIE_SECURE")
    assert not hasattr(settings, "SESSION_COOKIE_SECURE")


def test_settings_sets_secure_cookie_flags_when_debug_false(tmp_path):
    # Arrange: same patched logic, but DEBUG=False to ensure the new code path executes
    patched_source = (
        "DEBUG = False\n"
        "\n"
        "if not DEBUG:\n"
        "    CSRF_COOKIE_SECURE = True\n"
        "    SESSION_COOKIE_SECURE = True\n"
    )

    # Act
    settings = _import_settings_module_from_source(tmp_path, patched_source)

    # Assert: secure flags are enabled when DEBUG=False
    assert settings.DEBUG is False
    assert settings.CSRF_COOKIE_SECURE is True
    assert settings.SESSION_COOKIE_SECURE is True
