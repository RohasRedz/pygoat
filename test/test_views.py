import types

import pytest

# Assumption: Django app module path is "introduction.views" as per source file path.
import introduction.views as views


class _DummyUser:
    def __init__(self, authenticated=True):
        self.is_authenticated = authenticated


class _DummyRequest:
    def __init__(self, method="POST", post=None, user_authenticated=True):
        self.method = method
        self.POST = post or {}
        self.user = _DummyUser(user_authenticated)


def test_ssrf_lab2_rejects_untrusted_or_non_https_url(mocker):
    # Arrange
    req = _DummyRequest(post={"url": "http://127.0.0.1/admin"}, user_authenticated=True)

    render_spy = mocker.patch.object(views, "render", autospec=True)
    requests_get = mocker.patch.object(views.requests, "get", autospec=True)

    # Act
    views.ssrf_lab2(req)

    # Assert
    requests_get.assert_not_called()
    render_spy.assert_called_once()
    args, kwargs = render_spy.call_args
    assert args[1] == "Lab/ssrf/ssrf_lab2.html"
    assert kwargs["context"] == {"error": "Invalid or untrusted URL"}


def test_ssrf_lab2_allows_https_trusted_domain_and_calls_requests_get(mocker):
    # Arrange
    req = _DummyRequest(post={"url": "https://trusted-domain.com/path"}, user_authenticated=True)

    mock_response = types.SimpleNamespace(content=b"OK")
    requests_get = mocker.patch.object(views.requests, "get", autospec=True, return_value=mock_response)
    render_spy = mocker.patch.object(views, "render", autospec=True)

    # Act
    views.ssrf_lab2(req)

    # Assert
    requests_get.assert_called_once_with("https://trusted-domain.com/path")
    render_spy.assert_called_once()
    args, kwargs = render_spy.call_args
    assert args[1] == "Lab/ssrf/ssrf_lab2.html"
    assert kwargs["context"] == {"response": "OK"}


def test_ssrf_lab2_handles_requests_exception_with_invalid_url_error(mocker):
    # Arrange
    req = _DummyRequest(post={"url": "https://trusted-domain.com/path"}, user_authenticated=True)

    mocker.patch.object(views.requests, "get", autospec=True, side_effect=Exception("boom"))
    render_spy = mocker.patch.object(views, "render", autospec=True)

    # Act
    views.ssrf_lab2(req)

    # Assert
    render_spy.assert_called_once()
    args, kwargs = render_spy.call_args
    assert args[1] == "Lab/ssrf/ssrf_lab2.html"
    assert kwargs["context"] == {"error": "Invalid URL"}
