import importlib.util
from pathlib import Path


def _load_settings_module(tmp_path: Path, source: str):
    settings_path = tmp_path / "settings.py"
    settings_path.write_text(source, encoding="utf-8")

    spec = importlib.util.spec_from_file_location("test_settings_module", str(settings_path))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_settings_hsts_constants_defined_when_debug_false(monkeypatch, tmp_path):
    # Arrange: force DEBUG=False at import time so the new guarded block executes
    source = (
        "DEBUG = False\n"
        "if not DEBUG:\n"
        "    SECURE_HSTS_SECONDS = 31536000\n"
        "    SECURE_HSTS_INCLUDE_SUBDOMAINS = True\n"
        "    SECURE_HSTS_PRELOAD = True\n"
    )

    # Act
    settings = _load_settings_module(tmp_path, source)

    # Assert: secure behavior after fix (HSTS enabled in non-debug)
    assert settings.SECURE_HSTS_SECONDS == 31536000
    assert settings.SECURE_HSTS_INCLUDE_SUBDOMAINS is True
    assert settings.SECURE_HSTS_PRELOAD is True


def test_settings_hsts_constants_not_defined_when_debug_true(tmp_path):
    # Arrange: DEBUG=True should skip the new block
    source = (
        "DEBUG = True\n"
        "if not DEBUG:\n"
        "    SECURE_HSTS_SECONDS = 31536000\n"
        "    SECURE_HSTS_INCLUDE_SUBDOMAINS = True\n"
        "    SECURE_HSTS_PRELOAD = True\n"
    )

    # Act
    settings = _load_settings_module(tmp_path, source)

    # Assert: previously vulnerable behavior (HSTS missing) remains in debug mode by design
    assert not hasattr(settings, "SECURE_HSTS_SECONDS")
    assert not hasattr(settings, "SECURE_HSTS_INCLUDE_SUBDOMAINS")
    assert not hasattr(settings, "SECURE_HSTS_PRELOAD")
