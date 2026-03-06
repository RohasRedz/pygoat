import os

import pytest

from introduction import views


def _make_authenticated_request(mocker, blog_value):
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST.__getitem__.side_effect = lambda k: blog_value if k == "blog" else None
    return request


def test_ssrf_lab_rejects_directory_traversal_and_does_not_open(mocker):
    request = _make_authenticated_request(mocker, "../secrets.txt")

    open_mock = mocker.patch("builtins.open", side_effect=AssertionError("open should not be called"))
    render_mock = mocker.patch("introduction.views.render", return_value="rendered")

    result = views.ssrf_lab(request)

    assert result == "rendered"
    open_mock.assert_not_called()
    render_mock.assert_called()


def test_ssrf_lab_uses_basename_when_opening(mocker):
    request = _make_authenticated_request(mocker, "nested/path/blog.txt")

    mocker.patch("introduction.views.os.path.isabs", return_value=False)
    mocker.patch("introduction.views.os.path.normpath", side_effect=os.path.normpath)

    mocker.patch("introduction.views.os.path.dirname", return_value="/app/introduction")
    mocker.patch("introduction.views.os.path.basename", side_effect=os.path.basename)
    join_mock = mocker.patch("introduction.views.os.path.join", side_effect=lambda a, b: f"{a}/{b}")

    file_handle = mocker.Mock()
    file_handle.__enter__ = mocker.Mock(return_value=file_handle)
    file_handle.__exit__ = mocker.Mock(return_value=False)
    file_handle.read.return_value = "BLOG"
    open_mock = mocker.patch("builtins.open", return_value=file_handle)

    render_mock = mocker.patch("introduction.views.render", return_value="rendered")

    result = views.ssrf_lab(request)

    assert result == "rendered"
    join_mock.assert_called_once_with("/app/introduction", "blog.txt")
    open_mock.assert_called_once()
    render_mock.assert_called_once()
