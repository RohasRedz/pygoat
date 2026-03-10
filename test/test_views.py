import os

import pytest

# Assumption: repository root is on PYTHONPATH and Django app module is `introduction`.
# The patched function is `ssrf_lab` in `introduction/views.py`.
from introduction import views


def test_ssrf_lab_blocks_directory_traversal_dotdot(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": "../secret.txt"}

    # Ensure the new guard triggers before any filesystem access.
    mock_open = mocker.patch("builtins.open", autospec=True)

    # Render is called in the except path; return a sentinel so we can assert it.
    sentinel_response = object()
    mock_render = mocker.patch.object(views, "render", return_value=sentinel_response)

    # Act
    resp = views.ssrf_lab(request)

    # Assert
    assert resp is sentinel_response
    mock_open.assert_not_called()
    mock_render.assert_called_once()
    assert mock_render.call_args[0][1] == "Lab/ssrf/ssrf_lab.html"
    assert mock_render.call_args[0][2] == {"blog": "No blog found"}


def test_ssrf_lab_blocks_absolute_path(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": os.path.abspath("etc/passwd")}

    mock_open = mocker.patch("builtins.open", autospec=True)

    sentinel_response = object()
    mock_render = mocker.patch.object(views, "render", return_value=sentinel_response)

    # Act
    resp = views.ssrf_lab(request)

    # Assert
    assert resp is sentinel_response
    mock_open.assert_not_called()
    mock_render.assert_called_once()
    assert mock_render.call_args[0][2] == {"blog": "No blog found"}
