import pytest


# Assumptions:
# - Module path is "introduction.views" as implied by file_path.
from introduction import views


def _make_request(authenticated: bool = True, method: str = "POST"):
    class _User:
        is_authenticated = authenticated

    class _Req:
        def __init__(self):
            self.user = _User()
            self.method = method
            self.POST = {"url": "http://169.254.169.254/latest/meta-data"}

    return _Req()


def test_ssrf_lab2_ignores_user_supplied_url_and_uses_safe_endpoint(mocker):
    # Arrange
    req = _make_request()

    requests_get_mock = mocker.Mock()
    requests_get_mock.return_value.content = b"ok"
    mocker.patch.object(views.requests, "get", requests_get_mock)

    mocker.patch.object(views, "render", lambda request, template, ctx=None: {"template": template, "ctx": ctx or {}})

    # Act
    result = views.ssrf_lab2(req)

    # Assert
    requests_get_mock.assert_called_once_with("https://<your-safe-endpoint.com>")
    assert result["ctx"]["response"] == "ok"
