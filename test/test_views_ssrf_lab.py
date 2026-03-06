import os
import types

import pytest


def _make_request(blog_value: str, authenticated=True):
    user = types.SimpleNamespace(is_authenticated=authenticated)
    return types.SimpleNamespace(method="POST", POST={"blog": blog_value}, user=user)


def test_ssrf_lab_rejects_directory_traversal_and_does_not_open_file(monkeypatch):
    import introduction.views as views

    opened = {"called": False}

    def fake_open(*args, **kwargs):
        opened["called"] = True
        raise AssertionError("open() should not be called for traversal paths")

    monkeypatch.setattr(views, "open", fake_open, raising=True)
    monkeypatch.setattr(views, "render", lambda request, template, context=None: (template, context))

    req = _make_request("../secret.txt")
    template, ctx = views.ssrf_lab(req)

    assert opened["called"] is False
    assert template == "Lab/ssrf/ssrf_lab.html"
    assert ctx == {"blog": "No blog found"}


def test_ssrf_lab_uses_basename_and_opens_only_safe_file(monkeypatch):
    import introduction.views as views

    captured = {}

    def fake_open(path, mode="r"):
        captured["path"] = path
        captured["mode"] = mode

        class _FH:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, exc_type, exc, tb):
                return False

            def read(self_inner):
                return "BLOG_CONTENT"

        return _FH()

    monkeypatch.setattr(views, "open", fake_open, raising=True)
    monkeypatch.setattr(views.os.path, "dirname", lambda _p: "/base")
    monkeypatch.setattr(views, "render", lambda request, template, context=None: (template, context))

    req = _make_request("nested/dir/blog.txt")
    template, ctx = views.ssrf_lab(req)

    assert template == "Lab/ssrf/ssrf_lab.html"
    assert ctx == {"blog": "BLOG_CONTENT"}
    assert captured["path"] == os.path.join("/base", "blog.txt")
