import pytest

# Assumption: tests run with repo root on PYTHONPATH so "introduction" is importable.
from introduction import views


def test_ssrf_lab2_rejects_non_allowlisted_hostname(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"url": "http://127.0.0.1/admin"}

    render_mock = mocker.patch("introduction.views.render", return_value="rendered")
    requests_get_mock = mocker.patch("introduction.views.requests.get")

    # Act
    result = views.ssrf_lab2(request)

    # Assert
    assert result == "rendered"
    requests_get_mock.assert_not_called()
    render_mock.assert_called_once()
    _, _, context = render_mock.call_args[0]
    assert context == {"error": "Invalid URL"}
