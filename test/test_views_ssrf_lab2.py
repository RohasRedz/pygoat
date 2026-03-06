import types

import pytest


def _make_request(authenticated=True):
    user = types.SimpleNamespace(is_authenticated=authenticated)
    return types.SimpleNamespace(method="POST", POST={"url": "http://169.254.169.254/latest/meta-data"}, user=user)


def test_ssrf_lab2_ignores_user_supplied_url_and_uses_safe_endpoint(monkeypatch):
    import introduction.views as views

    called = {}

    class FakeResp:
        content = b"OK"

    def fake_get(url):
        called["url"] = url
        return FakeResp()

    monkeypatch.setattr(views.requests, "get", fake_get)
    monkeypatch.setattr(views, "render", lambda request, template, context=None: (template, context))

    req = _make_request()
    template, ctx = views.ssrf_lab2(req)

    assert called["url"] == "https://<your-safe-endpoint.com>"
    assert template == "Lab/ssrf/ssrf_lab2.html"
    assert ctx == {"response": "OK"}
