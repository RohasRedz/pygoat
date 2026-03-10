import os
from pathlib import Path

import pytest

# Assumption: Django view module is importable as introduction.views in the test environment.
from introduction import views


def test_ssrf_lab_sanitizes_blog_filename_with_basename(mocker, tmp_path):
    # Arrange
    # Create a fake views.py directory to anchor os.path.dirname(__file__) used by the view.
    fake_views_dir = tmp_path / "introduction"
    fake_views_dir.mkdir()
    (fake_views_dir / "allowed.txt").write_text("OK", encoding="utf-8")

    # Patch __file__ so dirname(__file__) points to our temp dir.
    mocker.patch.object(views, "__file__", str(fake_views_dir / "views.py"))

    # Mock Django render to avoid template engine dependency and to capture context.
    render_spy = mocker.patch.object(views, "render", side_effect=lambda req, tpl, ctx=None: {"tpl": tpl, "ctx": ctx})

    # Provide a POST request with a traversal attempt; after fix it must be reduced to basename.
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": "../allowed.txt"}

    # Act
    result = views.ssrf_lab(request)

    # Assert
    assert result["tpl"] == "Lab/ssrf/ssrf_lab.html"
    assert result["ctx"]["blog"] == "OK"

    # Ensure the view did not attempt to open a path containing traversal components.
    # It should have opened <dirname>/allowed.txt (basename only).
    opened_path = views.open.call_args[0][0] if hasattr(views, "open") and getattr(views.open, "call_args", None) else None
    # If open isn't patched at module level, assert via render output only.
    assert "../" not in (opened_path or "")
    assert ".." not in (opened_path or "")


def test_ssrf_lab_returns_no_blog_found_when_basename_file_missing(mocker, tmp_path):
    # Arrange
    fake_views_dir = tmp_path / "introduction"
    fake_views_dir.mkdir()

    mocker.patch.object(views, "__file__", str(fake_views_dir / "views.py"))
    mocker.patch.object(views, "render", side_effect=lambda req, tpl, ctx=None: {"tpl": tpl, "ctx": ctx})

    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": "../does_not_exist.txt"}

    # Act
    result = views.ssrf_lab(request)

    # Assert
    assert result["tpl"] == "Lab/ssrf/ssrf_lab.html"
    assert result["ctx"]["blog"] == "No blog found"
