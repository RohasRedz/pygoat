import os
import types

import pytest

# Assumption: tests run from repo root and "introduction" is an importable package.
from introduction import views


def _make_request(user_authenticated: bool, method: str = "POST", blog_value: str = "blog.txt"):
    user = types.SimpleNamespace(is_authenticated=user_authenticated)
    post = {"blog": blog_value} if method == "POST" else {}
    return types.SimpleNamespace(user=user, method=method, POST=post)


def test_ssrf_lab_rejects_absolute_path_before_open(mocker):
    # Arrange
    request = _make_request(user_authenticated=True, method="POST", blog_value="/etc/passwd")
    render_spy = mocker.patch("introduction.views.render", return_value="RENDERED")
    open_spy = mocker.patch("builtins.open", side_effect=AssertionError("open() must not be called for invalid paths"))

    # Act
    result = views.ssrf_lab(request)

    # Assert
    assert result == "RENDERED"
    open_spy.assert_not_called()
    render_spy.assert_called_with(request, "Lab/ssrf/ssrf_lab.html", {"blog": "Invalid file path"})


def test_ssrf_lab_rejects_parent_traversal_before_open(mocker):
    # Arrange
    request = _make_request(user_authenticated=True, method="POST", blog_value="../secrets.txt")
    render_spy = mocker.patch("introduction.views.render", return_value="RENDERED")
    open_spy = mocker.patch("builtins.open", side_effect=AssertionError("open() must not be called for invalid paths"))

    # Act
    result = views.ssrf_lab(request)

    # Assert
    assert result == "RENDERED"
    open_spy.assert_not_called()
    render_spy.assert_called_with(request, "Lab/ssrf/ssrf_lab.html", {"blog": "Invalid file path"})


def test_ssrf_lab_rejects_path_that_escapes_base_dir_after_normalization(mocker):
    # Arrange
    # This input does not contain ".." and is not absolute, but can still escape if join/abspath is subverted.
    request = _make_request(user_authenticated=True, method="POST", blog_value="safe.txt")
    render_spy = mocker.patch("introduction.views.render", return_value="RENDERED")
    open_spy = mocker.patch("builtins.open", side_effect=AssertionError("open() must not be called for escaped paths"))

    # Force the computed absolute path to be outside the base directory to exercise the startswith() guard.
    mocker.patch("introduction.views.os.path.abspath", side_effect=["/base/dir", "/other/place/safe.txt"])

    # Act
    result = views.ssrf_lab(request)

    # Assert
    assert result == "RENDERED"
    open_spy.assert_not_called()
    render_spy.assert_called_with(request, "Lab/ssrf/ssrf_lab.html", {"blog": "Invalid file path"})


def test_ssrf_lab_allows_safe_relative_path_and_opens_joined_file(mocker, tmp_path):
    # Arrange
    request = _make_request(user_authenticated=True, method="POST", blog_value="blog.txt")

    # Make dirname deterministic and point it at a temp directory containing the blog file.
    mocker.patch("introduction.views.os.path.dirname", return_value=str(tmp_path))
    blog_path = tmp_path / "blog.txt"
    blog_path.write_text("hello", encoding="utf-8")

    render_spy = mocker.patch("introduction.views.render", return_value="RENDERED")

    # Act
    result = views.ssrf_lab(request)

    # Assert
    assert result == "RENDERED"
    render_spy.assert_called_with(request, "Lab/ssrf/ssrf_lab.html", {"blog": "hello"})
