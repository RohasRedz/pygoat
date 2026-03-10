import importlib

import pytest


def _import_views_module():
    # Assumption: repository root is on PYTHONPATH and module is importable as "introduction.views"
    return importlib.import_module("introduction.views")


def test_ssrf_lab_rejects_parent_directory_traversal(mocker):
    # Arrange
    views = _import_views_module()

    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": "../secret.txt"}

    render_spy = mocker.patch.object(views, "render", autospec=True)

    # Act
    result = views.ssrf_lab(request)

    # Assert
    render_spy.assert_called_once()
    args, kwargs = render_spy.call_args
    assert args[1] == "Lab/ssrf/ssrf_lab.html"
    assert args[2] == {"blog": "Invalid file path provided"}
    assert result == render_spy.return_value


def test_ssrf_lab_rejects_absolute_path(mocker):
    # Arrange
    views = _import_views_module()

    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": "/etc/passwd"}

    render_spy = mocker.patch.object(views, "render", autospec=True)

    # Act
    result = views.ssrf_lab(request)

    # Assert
    render_spy.assert_called_once()
    args, kwargs = render_spy.call_args
    assert args[1] == "Lab/ssrf/ssrf_lab.html"
    assert args[2] == {"blog": "Invalid file path provided"}
    assert result == render_spy.return_value


def test_ssrf_lab_allows_safe_relative_filename_and_reads_file(mocker):
    # Arrange
    views = _import_views_module()

    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": "safe.txt"}

    # Avoid touching filesystem; ensure we don't hit the new rejection branch.
    mocker.patch.object(views.os.path, "isabs", autospec=True, return_value=False)
    join_spy = mocker.patch.object(views.os.path, "join", autospec=True, return_value="/base/safe.txt")

    fake_file = mocker.Mock()
    fake_file.read.return_value = "BLOG_CONTENT"
    open_spy = mocker.patch.object(views, "open", create=True, return_value=fake_file)

    render_spy = mocker.patch.object(views, "render", autospec=True)

    # Act
    result = views.ssrf_lab(request)

    # Assert
    join_spy.assert_called_once()
    open_spy.assert_called_once_with("/base/safe.txt", "r")
    fake_file.read.assert_called_once()
    render_spy.assert_called_once()
    args, kwargs = render_spy.call_args
    assert args[1] == "Lab/ssrf/ssrf_lab.html"
    assert args[2] == {"blog": "BLOG_CONTENT"}
    assert result == render_spy.return_value
