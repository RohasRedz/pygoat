import pytest

# Assumption: "introduction" is importable from tests.
from introduction import views


def test_ssrf_lab_blocks_absolute_or_parent_traversal_paths(mocker):
    # Arrange
    request = mocker.Mock()
    request.user = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": "../secrets.txt"}

    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())
    open_mock = mocker.patch("builtins.open", create=True)

    # Act
    views.ssrf_lab(request)

    # Assert: should short-circuit before open()
    open_mock.assert_not_called()
    render_mock.assert_called()
    _, _, context = render_mock.call_args[0]
    assert context["blog"] == "Invalid file request."
