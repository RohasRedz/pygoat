import pytest

from introduction import views


def test_ssrf_lab2_ignores_user_supplied_url_and_uses_safe_endpoint(mocker):
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST.__getitem__.return_value = "http://169.254.169.254/latest/meta-data"

    get_mock = mocker.patch("introduction.views.requests.get", return_value=mocker.Mock(content=b"OK"))
    render_mock = mocker.patch("introduction.views.render", return_value="rendered")

    result = views.ssrf_lab2(request)

    assert result == "rendered"
    get_mock.assert_called_once_with("https://<your-safe-endpoint.com>")
    render_mock.assert_called_once()
