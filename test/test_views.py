import pytest

# Assumption: Django app module path is "introduction.views" based on file_path "introduction/views.py".
from introduction import views


def test_ssrf_lab2_post_ignores_user_supplied_url_and_uses_safe_url(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"url": "http://169.254.169.254/latest/meta-data"}  # classic SSRF target

    requests_get = mocker.patch("introduction.views.requests.get")
    response = mocker.Mock()
    response.content = b"ok"
    requests_get.return_value = response

    render = mocker.patch("introduction.views.render", return_value=mocker.Mock())

    # Act
    views.ssrf_lab2(request)

    # Assert
    requests_get.assert_called_once_with("https://trusted.example.com/api")
    render.assert_called_once()
