import os

import pytest

# Assumption: Django app module path is "introduction.views" based on file_path "introduction/views.py"
from introduction import views


def test_ssrf_lab_rejects_non_allowlisted_blog_key_and_does_not_open_file(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": "../../etc/passwd"}

    open_mock = mocker.patch("builtins.open")
    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    resp = views.ssrf_lab(request)

    # Assert
    open_mock.assert_not_called()
    render_mock.assert_called_once()
    _, template, context = render_mock.call_args[0]
    assert template == "Lab/ssrf/ssrf_lab.html"
    assert context == {"blog": "Invalid file"}
    assert resp is render_mock.return_value


def test_ssrf_lab_allows_default_blog_and_opens_resolved_path_under_base_dir(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": "default"}

    # Make dirname deterministic
    mocker.patch.object(views.os.path, "dirname", return_value="/app/introduction")
    mocker.patch.object(views.os.path, "abspath", side_effect=lambda p: p)
    mocker.patch.object(views.os.path, "normpath", side_effect=lambda p: p)
    mocker.patch.object(views.os.path, "join", side_effect=lambda a, b: f"{a}/{b}")

    f = mocker.Mock()
    f.read.return_value = "BLOG"
    open_mock = mocker.patch("builtins.open", return_value=f)
    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    resp = views.ssrf_lab(request)

    # Assert
    open_mock.assert_called_once_with("/app/introduction/blog.txt", "r")
    render_mock.assert_called_once()
    _, template, context = render_mock.call_args[0]
    assert template == "Lab/ssrf/ssrf_lab.html"
    assert context == {"blog": "BLOG"}
    assert resp is render_mock.return_value
