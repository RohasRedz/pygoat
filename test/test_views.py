import os

import pytest

# Assumption: Django app module path is "introduction.views" as per source file path.
import introduction.views as views


class _DummyUser:
    def __init__(self, authenticated=True):
        self.is_authenticated = authenticated


class _DummyRequest:
    def __init__(self, method="POST", post=None, user_authenticated=True):
        self.method = method
        self.POST = post or {}
        self.user = _DummyUser(user_authenticated)


def test_ssrf_lab_rejects_non_whitelisted_file_key(mocker):
    # Arrange
    req = _DummyRequest(post={"blog": "../../etc/passwd"}, user_authenticated=True)

    render_spy = mocker.patch.object(views, "render", autospec=True)
    open_spy = mocker.patch("builtins.open", autospec=True)

    # Act
    views.ssrf_lab(req)

    # Assert
    open_spy.assert_not_called()
    render_spy.assert_called_once()
    args, kwargs = render_spy.call_args
    assert args[1] == "Lab/ssrf/ssrf_lab.html"
    assert kwargs["context"] == {"blog": "Invalid file request"}


def test_ssrf_lab_allows_whitelisted_blog_key_and_reads_blog_txt(mocker, tmp_path):
    # Arrange
    req = _DummyRequest(post={"blog": "blog"}, user_authenticated=True)

    # Ensure os.path.join(dirname, 'blog.txt') is opened.
    dirname = os.path.dirname(views.__file__)
    expected_path = os.path.join(dirname, "blog.txt")

    m = mocker.mock_open(read_data="BLOG CONTENT")
    open_mock = mocker.patch("builtins.open", m)
    render_spy = mocker.patch.object(views, "render", autospec=True)

    # Act
    views.ssrf_lab(req)

    # Assert
    open_mock.assert_called_once_with(expected_path, "r")
    args, kwargs = render_spy.call_args
    assert args[1] == "Lab/ssrf/ssrf_lab.html"
    assert kwargs["context"] == {"blog": "BLOG CONTENT"}
