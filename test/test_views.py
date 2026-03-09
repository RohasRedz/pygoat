import pytest

# Assumption: Django app module path is "introduction.views" based on file_path "introduction/views.py"
from introduction import views


def test_ssrf_lab2_rejects_unallowlisted_url_key_and_does_not_call_requests_get(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"url_key": "http://169.254.169.254/latest/meta-data"}  # SSRF-style payload

    requests_get = mocker.patch.object(views.requests, "get")
    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    resp = views.ssrf_lab2(request)

    # Assert
    requests_get.assert_not_called()
    render_mock.assert_called_once()
    _, template, context = render_mock.call_args[0]
    assert template == "Lab/ssrf/ssrf_lab2.html"
    assert context == {"error": "Invalid or unauthorized URL"}
    assert resp is render_mock.return_value


def test_ssrf_lab2_allows_only_known_keys_and_calls_requests_get_with_allowlisted_url(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"url_key": "option1"}

    response = mocker.Mock()
    response.content = b"ok"
    requests_get = mocker.patch.object(views.requests, "get", return_value=response)
    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    resp = views.ssrf_lab2(request)

    # Assert
    requests_get.assert_called_once_with("https://safe1.example.com/api")
    render_mock.assert_called_once()
    _, template, context = render_mock.call_args[0]
    assert template == "Lab/ssrf/ssrf_lab2.html"
    assert context == {"response": "ok"}
    assert resp is render_mock.return_value
