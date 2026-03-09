import importlib
import types

import pytest


def _import_views_module():
    # Assumption: Django app module path is "introduction.views" based on file_path.
    return importlib.import_module("introduction.views")


def test_ssrf_lab2_blocks_non_allowlisted_url_and_does_not_call_requests_get(mocker):
    """
    Delta test for SSRF allowlist:
    - Previously: requests.get was called with user-controlled URL.
    - Now: non-allowlisted URL returns error and must not call requests.get.
    """
    views = _import_views_module()

    # Arrange
    request = types.SimpleNamespace(
        method="POST",
        POST={"url": "http://127.0.0.1:8000/internal"},
    )

    requests_get_mock = mocker.patch.object(views.requests, "get", autospec=True)
    render_mock = mocker.patch.object(views, "render", return_value="rendered")

    # Act
    result = views.ssrf_lab2(request)

    # Assert
    requests_get_mock.assert_not_called()
    assert result == "rendered"
    render_mock.assert_called()
    _, _, kwargs = render_mock.mock_calls[-1]
    assert kwargs["context"]["error"] == "Invalid URL"
