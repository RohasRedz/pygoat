import os

import pytest

# Assumption: module path is "introduction.views" based on file_path "introduction/views.py"
import introduction.views as views


def _make_request(authenticated=True, method="POST", blog_value="blog.txt"):
    class _User:
        is_authenticated = authenticated

    class _Request:
        user = _User()
        method = method
        POST = {"blog": blog_value}

    return _Request()


def test_ssrf_lab_rejects_directory_traversal_paths(mocker):
    # Arrange
    request = _make_request(blog_value="../secret.txt")
    render_spy = mocker.patch.object(views, "render", autospec=True)
    open_spy = mocker.patch.object(views, "open", autospec=True)

    # Act
    views.ssrf_lab(request)

    # Assert: should short-circuit and not attempt to open any file
    open_spy.assert_not_called()
    render_spy.assert_called_once()
    args, kwargs = render_spy.call_args
    assert args[1] == "Lab/ssrf/ssrf_lab.html"
    assert args[2]["blog"] == "Invalid file path provided."


def test_ssrf_lab_rejects_absolute_paths(mocker):
    # Arrange
    abs_path = os.path.abspath("secret.txt")
    request = _make_request(blog_value=abs_path)
    render_spy = mocker.patch.object(views, "render", autospec=True)
    open_spy = mocker.patch.object(views, "open", autospec=True)

    # Act
    views.ssrf_lab(request)

    # Assert
    open_spy.assert_not_called()
    render_spy.assert_called_once()
    args, kwargs = render_spy.call_args
    assert args[1] == "Lab/ssrf/ssrf_lab.html"
    assert args[2]["blog"] == "Invalid file path provided."


def test_ssrf_lab_allows_normal_relative_path_and_opens_joined_file(mocker):
    # Arrange
    request = _make_request(blog_value="safe_blog.txt")
    mocker.patch.object(views, "render", autospec=True, return_value="RENDERED")
    mocker.patch.object(views.os.path, "dirname", autospec=True, return_value="/base")
    join_spy = mocker.patch.object(views.os.path, "join", autospec=True, return_value="/base/safe_blog.txt")

    fake_file = mocker.Mock()
    fake_file.read.return_value = "BLOG_CONTENT"
    open_spy = mocker.patch.object(views, "open", autospec=True, return_value=fake_file)

    # Act
    result = views.ssrf_lab(request)

    # Assert
    assert result == "RENDERED"
    join_spy.assert_called_once_with("/base", "safe_blog.txt")
    open_spy.assert_called_once_with("/base/safe_blog.txt", "r")
