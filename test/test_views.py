# Assumption: project root is on PYTHONPATH so `import introduction.views` works in tests.

import types

import pytest

import introduction.views as views


def _make_request(url: str):
    return types.SimpleNamespace(method="POST", POST={"url": url})


def test_ssrf_lab2_blocks_non_approved_domain_and_does_not_call_requests_get(monkeypatch):
    # Arrange
    def _requests_get_should_not_be_called(*args, **kwargs):
        raise AssertionError("requests.get must not be called when URL is not allowed")

    def _fake_render(request, template, context=None):
        # Return context so we can assert on it without Django test client.
        return {"template": template, "context": context or {}}

    monkeypatch.setattr(views.requests, "get", _requests_get_should_not_be_called)
    monkeypatch.setattr(views, "render", _fake_render)

    # Act
    result = views.ssrf_lab2(_make_request("http://127.0.0.1/admin"))

    # Assert
    assert result["template"] == "Lab/ssrf/ssrf_lab2.html"
    assert result["context"]["error"] == "URL not allowed"
