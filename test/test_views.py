import importlib
import types

import pytest


def _import_views_module():
    # Assumption: Django app module path is "introduction.views" based on file_path.
    return importlib.import_module("introduction.views")


def test_ssrf_lab_allows_only_allowlisted_blog_key_and_blocks_path_traversal(mocker):
    """
    Delta test for path traversal fix in ssrf_lab:
    - Previously: user-controlled 'blog' value was joined into a filesystem path.
    - Now: only allowlisted key 'blog' is permitted (maps to 'blog.txt').
    """
    views = _import_views_module()

    # Arrange
    user = types.SimpleNamespace(is_authenticated=True)

    # Simulate POST with a traversal attempt
    request = types.SimpleNamespace(
        user=user,
        method="POST",
        POST={"blog": "../../etc/passwd"},
    )

    render_mock = mocker.patch.object(views, "render", return_value="rendered")
    open_mock = mocker.patch("builtins.open", autospec=True)

    # Act
    result = views.ssrf_lab(request)

    # Assert: should not attempt to open any file for non-allowlisted key
    open_mock.assert_not_called()
    assert result == "rendered"
    render_mock.assert_called()
    # Ensure it returned the "No blog found" branch (broad except in code)
    _, _, kwargs = render_mock.mock_calls[-1]
    assert kwargs["context"]["blog"] == "No blog found"
