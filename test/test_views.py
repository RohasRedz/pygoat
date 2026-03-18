import types

import pytest


# Assumptions:
# - Django is installed and importable in the test environment.
# - The project module path is "introduction.views".


def _make_request(*, method="POST", authenticated=True):
    user = types.SimpleNamespace(is_authenticated=authenticated)
    return types.SimpleNamespace(method=method, user=user, POST={"url": "http://169.254.169.254/latest/meta-data"})


def test_ssrf_lab2_ignores_user_supplied_url_and_uses_safe_constant(mocker):
    from introduction import views

    request = _make_request()

    response_obj = types.SimpleNamespace(content=b"OK")
    get_mock = mocker.patch.object(views.requests, "get", autospec=True, return_value=response_obj)

    mocker.patch.object(views, "render", autospec=True)

    views.ssrf_lab2(request)

    get_mock.assert_called_once_with("https://safe.example.com/resource")
