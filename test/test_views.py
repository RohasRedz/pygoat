# test/test_views.py
# Assumption: Django app module is "introduction" and tests run with pytest + pytest-django.
import pytest

from introduction import views


@pytest.mark.parametrize(
    "raw_url",
    [
        "http://trusted-domain.com/path",          # wrong scheme
        "https://evil.com/?u=trusted-domain.com",  # trusted string not in netloc
        "https://127.0.0.1/",                      # SSRF localhost
        "",                                        # missing url
    ],
)
def test_ssrf_lab2_rejects_untrusted_or_invalid_url(raw_url, mocker):
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"url": raw_url}

    render_spy = mocker.patch("introduction.views.render", return_value=mocker.Mock())
    requests_get_spy = mocker.patch("introduction.views.requests.get")

    resp = views.ssrf_lab2.__wrapped__(request)

    assert resp == render_spy.return_value
    render_spy.assert_called_once()
    assert render_spy.call_args[0][1] == "Lab/ssrf/ssrf_lab2.html"
    assert render_spy.call_args[0][2] == {"error": "Invalid or untrusted URL"}
    requests_get_spy.assert_not_called()


def test_ssrf_lab2_allows_https_trusted_domain_and_calls_requests_get(mocker):
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"url": "https://trusted-domain.com/safe"}

    fake_response = mocker.Mock()
    fake_response.content = b"ok"
    requests_get_spy = mocker.patch("introduction.views.requests.get", return_value=fake_response)
    render_spy = mocker.patch("introduction.views.render", return_value=mocker.Mock())

    resp = views.ssrf_lab2.__wrapped__(request)

    assert resp == render_spy.return_value
    requests_get_spy.assert_called_once_with("https://trusted-domain.com/safe")
    render_spy.assert_called_once_with(request, "Lab/ssrf/ssrf_lab2.html", {"response": "ok"})
