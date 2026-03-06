import pytest

# Assumption: Django app module path is "introduction.views" based on file_path "introduction/views.py".
from introduction import views


def test_ssrf_lab_rejects_directory_traversal_filename(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": "../secrets.txt"}

    render = mocker.patch("introduction.views.render", return_value=mocker.Mock())
    open_spy = mocker.patch("builtins.open", side_effect=AssertionError("open() must not be called for invalid path"))

    # Act
    views.ssrf_lab(request)

    # Assert
    render.assert_called_once()
    _, _, kwargs = render.mock_calls[0]
    assert kwargs["context"]["blog"] == "Invalid file name provided"
    open_spy.assert_not_called()
