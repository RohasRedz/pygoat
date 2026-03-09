import os
from types import SimpleNamespace

import pytest

# Assumption: tests run with repo root on PYTHONPATH so "introduction" is importable.
import introduction.views as views


def _make_request(blog_value: str):
    return SimpleNamespace(
        user=SimpleNamespace(is_authenticated=True),
        method="POST",
        POST={"blog": blog_value},
    )


def test_ssrf_lab_blocks_absolute_paths(monkeypatch):
    # Arrange: ensure open() is never reached for blocked input
    def _fail_open(*args, **kwargs):
        raise AssertionError("open() should not be called for absolute paths")

    monkeypatch.setattr(views, "open", _fail_open, raising=True)

    # Act
    resp = views.ssrf_lab(_make_request("/etc/passwd"))

    # Assert: render() returns an HttpResponse
    assert hasattr(resp, "status_code")
    assert resp.status_code == 200


def test_ssrf_lab_blocks_parent_directory_traversal(monkeypatch):
    # Arrange
    def _fail_open(*args, **kwargs):
        raise AssertionError("open() should not be called for traversal paths")

    monkeypatch.setattr(views, "open", _fail_open, raising=True)

    # Act
    resp = views.ssrf_lab(_make_request("../settings.py"))

    # Assert
    assert hasattr(resp, "status_code")
    assert resp.status_code == 200


def test_ssrf_lab_sanitizes_to_basename_before_open(monkeypatch, tmp_path):
    # Arrange
    opened = {}

    def _fake_dirname(_):
        return str(tmp_path)

    def _fake_open(path, mode="r", *args, **kwargs):
        opened["path"] = path

        class _F:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return "blog-content"

        return _F()

    monkeypatch.setattr(views.os.path, "dirname", _fake_dirname)
    monkeypatch.setattr(views, "open", _fake_open, raising=True)

    # Act
    resp = views.ssrf_lab(_make_request("subdir/ok.txt"))

    # Assert: only basename is used
    assert opened["path"] == os.path.join(str(tmp_path), "ok.txt")
    assert hasattr(resp, "status_code")
    assert resp.status_code == 200
