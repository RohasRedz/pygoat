import os

import pytest


# Assumption: tests run with repository root on PYTHONPATH so `introduction` is importable.
from introduction import views


def test_ssrf_lab_blocks_directory_traversal_and_does_not_open_file(monkeypatch):
    opened = {"called": False}

    def fake_open(*args, **kwargs):
        opened["called"] = True
        raise AssertionError("open() should not be called for traversal paths")

    monkeypatch.setattr(views, "open", fake_open, raising=True)
    monkeypatch.setattr(views, "render", lambda request, template, context=None: {"template": template, "context": context})

    class Req:
        user = type("U", (), {"is_authenticated": True})()
        method = "POST"
        POST = {"blog": "../secrets.txt"}

    resp = views.ssrf_lab(Req())

    assert opened["called"] is False
    assert resp["template"] == "Lab/ssrf/ssrf_lab.html"
    assert resp["context"] == {"blog": "No blog found"}


def test_ssrf_lab_uses_basename_when_joining_path(monkeypatch):
    # Ensure that even if a path contains separators, only basename is used.
    captured = {}

    def fake_open(path, mode="r"):
        captured["path"] = path

        class FH:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return "BLOG"

        return FH()

    monkeypatch.setattr(views, "open", fake_open, raising=True)
    monkeypatch.setattr(views, "render", lambda request, template, context=None: {"template": template, "context": context})

    class Req:
        user = type("U", (), {"is_authenticated": True})()
        method = "POST"
        POST = {"blog": "nested/dir/blog.txt"}

    resp = views.ssrf_lab(Req())

    assert resp["context"] == {"blog": "BLOG"}
    # The joined path should end with basename only
    assert os.path.basename(captured["path"]) == "blog.txt"
