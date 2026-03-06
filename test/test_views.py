import pytest

# Assumption: "introduction" is importable from tests.
from introduction import views


def test_ssrf_lab2_rejects_non_allowlisted_url_and_does_not_call_requests(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"url": "http://127.0.0.1/admin"}  # SSRF-style target

    requests_get_mock = mocker.patch.object(views.requests, "get")
    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    views.ssrf_lab2(request)

    # Assert
    requests_get_mock.assert_not_called()
    render_mock.assert_called()
    _, _, context = render_mock.call_args[0]
    assert context["error"] == "Invalid URL"
