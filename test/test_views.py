import pytest

# Assumption: "introduction" is importable from tests.
from introduction import views


def test_insec_desgine_lab_rejects_non_digit_count(mocker):
    # Arrange
    request = mocker.Mock()
    request.user = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"count": "1; DROP TABLE"}  # non-digit payload

    # Avoid DB access
    mocker.patch.object(views.tickits.objects, "filter", return_value=[])
    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    views.insec_desgine_lab(request)

    # Assert: should render error instead of int() conversion
    render_mock.assert_called()
    _, _, context = render_mock.call_args[0]
    assert context["error"] == "Invalid count value"


def test_insec_desgine_lab_rejects_count_exceeding_limit(mocker):
    # Arrange
    request = mocker.Mock()
    request.user = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"count": "6"}  # would exceed 5

    # Simulate existing tickets length = 0
    mocker.patch.object(views.tickits.objects, "filter", return_value=[])
    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    views.insec_desgine_lab(request)

    # Assert
    render_mock.assert_called()
    _, _, context = render_mock.call_args[0]
    assert context["error"] == "You can have at most 5 tickits"
