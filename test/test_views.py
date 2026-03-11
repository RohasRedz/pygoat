import os

import pytest

# Assumption: tests run from repo root and "introduction" is importable as a package.
from introduction import views


class _DummyUser:
    is_authenticated = True


class _DummyRequest:
    def __init__(self, blog_value: str):
        self.user = _DummyUser()
        self.method = "POST"
        self.POST = {"blog": blog_value}


def test_ssrf_lab_rejects_absolute_path_and_returns_no_blog_found(mocker):
    # Arrange
    req = _DummyRequest("/etc/passwd")
    render_spy = mocker.patch("introduction.views.render", return_value="RENDERED")
    open_spy = mocker.patch("builtins.open", autospec=True)

    # Act
    result = views.ssrf_lab(req)

    # Assert
    assert result == "RENDERED"
    open_spy.assert_not_called()
    render_spy.assert_called_with(req, "Lab/ssrf/ssrf_lab.html", {"blog": "No blog found"})


def test_ssrf_lab_rejects_directory_traversal_and_returns_no_blog_found(mocker):
    # Arrange
    req = _DummyRequest("../secrets.txt")
    render_spy = mocker.patch("introduction.views.render", return_value="RENDERED")
    open_spy = mocker.patch("builtins.open", autospec=True)

    # Act
    result = views.ssrf_lab(req)

    # Assert
    assert result == "RENDERED"
    open_spy.assert_not_called()
    render_spy.assert_called_with(req, "Lab/ssrf/ssrf_lab.html", {"blog": "No blog found"})


def test_ssrf_lab_allows_safe_relative_path_and_opens_resolved_path(mocker, tmp_path):
    # Arrange
    # Create a safe file under the same directory as views.py so the base-dir check passes.
    views_dir = os.path.dirname(views.__file__)
    safe_name = "unit_test_blog.txt"
    safe_path = os.path.join(views_dir, safe_name)
    try:
        with open(safe_path, "w", encoding="utf-8") as f:
            f.write("hello")

        req = _DummyRequest(safe_name)
        render_spy = mocker.patch("introduction.views.render", return_value="RENDERED")

        # Spy on open but still allow real file IO for deterministic content.
        open_spy = mocker.spy(__builtins__, "open")

        # Act
        result = views.ssrf_lab(req)

        # Assert
        assert result == "RENDERED"
        assert open_spy.call_count == 1
        opened_path = open_spy.call_args[0][0]
        assert os.path.abspath(opened_path) == os.path.abspath(safe_path)
        render_spy.assert_called_with(req, "Lab/ssrf/ssrf_lab.html", {"blog": "hello"})
    finally:
        try:
            os.remove(safe_path)
        except OSError:
            pass
