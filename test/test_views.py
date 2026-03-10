import os
import types

import pytest

import introduction.views as views


class _DummyUser:
    is_authenticated = True


class _DummyRequest:
    def __init__(self, blog_value: str):
        self.user = _DummyUser()
        self.method = "POST"
        self.POST = {"blog": blog_value}


def test_ssrf_lab_rejects_directory_traversal_before_open(monkeypatch):
    # Arrange: attempt to traverse outside the allowed directory
    req = _DummyRequest(blog_value=f"..{os.sep}..{os.sep}etc{os.sep}passwd")

    # If the fix works, it should fail before trying to open any file.
    def _open_should_not_be_called(*args, **kwargs):
        raise AssertionError("open() should not be called for directory traversal input")

    monkeypatch.setattr(views, "open", _open_should_not_be_called, raising=True)

    # Avoid needing Django templates: stub render() to a simple sentinel.
    sentinel = object()

    def _render_stub(*args, **kwargs):
        return sentinel

    monkeypatch.setattr(views, "render", _render_stub, raising=True)

    # Act
    result = views.ssrf_lab(req)

    # Assert: function handled the invalid path and returned the fallback render result
    assert result is sentinel
