from types import SimpleNamespace

import pytest


# Assumptions:
# - Module under test is importable as introduction.views.


def _make_authenticated_request():
    user = SimpleNamespace(is_authenticated=True)
    return SimpleNamespace(method="POST", POST={"url": "http://169.254.169.254/latest/meta-data"}, user=user)


def test_ssrf_lab2_ignores_user_supplied_url_and_uses_safe_endpoint(mocker):
    from introduction import views

    request = _make_authenticated_request()

    requests_get = mocker.patch("introduction.views.requests.get")
    requests_get.return_value = SimpleNamespace(content=b"ok")

    mocker.patch(
        "introduction.views.render",
        side_effect=lambda req, tpl, ctx=None: {"tpl": tpl, "ctx": ctx},
    )

    result = views.ssrf_lab2(request)

    requests_get.assert_called_once_with("https://<your-safe-endpoint.com>")
    assert result["ctx"]["response"] == "ok"
