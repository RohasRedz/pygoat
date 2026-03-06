import types

import pytest


def _make_request(url: str):
    user = types.SimpleNamespace(is_authenticated=True)
    return types.SimpleNamespace(method="POST", POST={"url": url}, user=user)


def test_ssrf_lab2_rejects_untrusted_or_non_https_url(mocker):
    # Regression test for SSRF fix: only https://trusted-domain.com/* is allowed.
    from introduction import views

    render_spy = mocker.patch("introduction.views.render", autospec=True)
    get_spy = mocker.patch("introduction.views.requests.get", autospec=True)

    req = _make_request("http://127.0.0.1/admin")
    views.ssrf_lab2(req)

    get_spy.assert_not_called()
    render_spy.assert_called()
    assert render_spy.call_args[0][1] == "Lab/ssrf/ssrf_lab2.html"
    assert render_spy.call_args[0][2]["error"] == "Invalid or untrusted URL"


def test_ssrf_lab2_allows_trusted_domain_https_and_calls_requests_get(mocker):
    from introduction import views

    render_spy = mocker.patch("introduction.views.render", autospec=True)
    get_spy = mocker.patch("introduction.views.requests.get", autospec=True)
    get_spy.return_value = types.SimpleNamespace(content=b"ok")

    req = _make_request("https://trusted-domain.com/path")
    views.ssrf_lab2(req)

    get_spy.assert_called_once_with("https://trusted-domain.com/path")
    render_spy.assert_called()
    assert render_spy.call_args[0][1] == "Lab/ssrf/ssrf_lab2.html"
    assert render_spy.call_args[0][2]["response"] == "ok"
