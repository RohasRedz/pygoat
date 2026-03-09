import os
import pytest

# Assumption: repository uses "introduction" as a top-level Python package.
from introduction import views


def test_ssrf_lab_rejects_absolute_path_and_does_not_open_file(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": "/etc/passwd"}

    open_spy = mocker.patch("builtins.open", autospec=True)
    render_spy = mocker.patch("introduction.views.render", autospec=True)

    # Act
    views.ssrf_lab(request)

    # Assert: secure behavior after fix - absolute paths are rejected and file is not opened
    open_spy.assert_not_called()
    render_spy.assert_called()
    _, _, context = render_spy.mock_calls[-1].args
    assert context == {"blog": "No blog found"}


def test_ssrf_lab_rejects_parent_traversal_and_does_not_open_file(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": "../secrets.txt"}

    open_spy = mocker.patch("builtins.open", autospec=True)
    render_spy = mocker.patch("introduction.views.render", autospec=True)

    # Act
    views.ssrf_lab(request)

    # Assert: traversal is rejected and file is not opened
    open_spy.assert_not_called()
    _, _, context = render_spy.mock_calls[-1].args
    assert context == {"blog": "No blog found"}


def test_ssrf_lab_allows_safe_relative_path_and_opens_normalized_path(mocker, tmp_path):
    # Arrange
    # Create a file that should be readable via a safe relative path
    blog_rel = "safe_blog.txt"
    blog_abs = tmp_path / blog_rel
    blog_abs.write_text("hello", encoding="utf-8")

    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": blog_rel}

    # Force __file__ dirname to tmp_path by patching os.path.dirname used in the function
    mocker.patch("introduction.views.os.path.dirname", return_value=str(tmp_path))

    render_spy = mocker.patch("introduction.views.render", autospec=True)

    # Act
    views.ssrf_lab(request)

    # Assert: file content is read and returned
    _, _, context = render_spy.mock_calls[-1].args
    assert context == {"blog": "hello"}
