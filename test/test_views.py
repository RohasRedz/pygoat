import os
import types

import pytest

# Assumption: repository uses standard Django app layout where `introduction` is importable.
from introduction import views


def _make_request(blog_value):
    # Minimal request stub for ssrf_lab: needs user.is_authenticated and POST["blog"]
    user = types.SimpleNamespace(is_authenticated=True)
    return types.SimpleNamespace(user=user, method="POST", POST={"blog": blog_value})


def test_ssrf_lab_blocks_directory_traversal_outside_base_dir(monkeypatch):
    # Arrange
    request = _make_request("../secrets.txt")

    # Make base_dir deterministic
    monkeypatch.setattr(views.os.path, "dirname", lambda _: "/app/introduction")
    monkeypatch.setattr(views.os.path, "realpath", lambda p: p)

    render_calls = []

    def fake_render(_request, template, context):
        render_calls.append((template, context))
        return {"template": template, "context": context}

    monkeypatch.setattr(views, "render", fake_render)

    # If the fix is correct, open() must never be called for traversal attempts
    def fail_open(*args, **kwargs):
        raise AssertionError("open() should not be called for out-of-scope paths")

    monkeypatch.setattr(views, "open", fail_open, raising=False)

    # Act
    resp = views.ssrf_lab(request)

    # Assert
    assert resp["template"] == "Lab/ssrf/ssrf_lab.html"
    assert resp["context"]["blog"] == "Invalid file path."
    assert render_calls, "render() should have been called"


def test_ssrf_lab_allows_in_scope_file_and_reads_contents(monkeypatch):
    # Arrange
    request = _make_request("blog.txt")

    monkeypatch.setattr(views.os.path, "dirname", lambda _: "/app/introduction")
    monkeypatch.setattr(views.os.path, "realpath", lambda p: p)

    def fake_render(_request, template, context):
        return {"template": template, "context": context}

    monkeypatch.setattr(views, "render", fake_render)

    class DummyFile:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return "BLOG_CONTENT"

    opened = {"path": None}

    def fake_open(path, mode="r", *args, **kwargs):
        opened["path"] = path
        assert mode == "r"
        return DummyFile()

    monkeypatch.setattr(views, "open", fake_open, raising=False)

    # Act
    resp = views.ssrf_lab(request)

    # Assert
    assert opened["path"] == os.path.join("/app/introduction", "blog.txt")
    assert resp["template"] == "Lab/ssrf/ssrf_lab.html"
    assert resp["context"]["blog"] == "BLOG_CONTENT"
