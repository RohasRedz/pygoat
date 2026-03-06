import pytest


# Assumption: tests run with repository root on PYTHONPATH so `introduction` is importable.
from introduction import views


def test_ssrf_lab2_ignores_user_supplied_url_and_uses_safe_endpoint(monkeypatch):
    captured = {}

    def fake_get(url):
        captured["url"] = url

        class Resp:
            content = b"OK"

        return Resp()

    monkeypatch.setattr(views.requests, "get", fake_get)
    monkeypatch.setattr(views, "render", lambda request, template, context=None: {"template": template, "context": context})

    class Req:
        user = type("U", (), {"is_authenticated": True})()
        method = "POST"
        POST = {"url": "http://169.254.169.254/latest/meta-data"}

    resp = views.ssrf_lab2(Req())

    assert captured["url"] == "https://<your-safe-endpoint.com>"
    assert resp["template"] == "Lab/ssrf/ssrf_lab2.html"
    assert resp["context"] == {"response": "OK"}
