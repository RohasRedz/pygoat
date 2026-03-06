import os

import pytest


# Assumptions:
# - Module path is "introduction.views" as implied by file_path.
from introduction import views


def _make_request(blog_value: str, authenticated: bool = True, method: str = "POST"):
    class _User:
        is_authenticated = authenticated

    class _Req:
        def __init__(self):
            self.user = _User()
            self.method = method
            self.POST = {"blog": blog_value}

    return _Req()


def test_ssrf_lab_rejects_directory_traversal_and_does_not_open_file(mocker):
    # Arrange
    req = _make_request("../secrets.txt")

    open_mock = mocker.patch("builtins.open", side_effect=AssertionError("open() should not be called"))
    render_mock = mocker.patch.object(views, "render", return_value="rendered")

    # Act
    result = views.ssrf_lab(req)

    # Assert
    assert result == "rendered"
    open_mock.assert_not_called()
    # Should fall back to "No blog found" on exception
    render_mock.assert_called_with(req, "Lab/ssrf/ssrf_lab.html", {"blog": "No blog found"})
