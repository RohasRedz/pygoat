import pytest

# Assumption: Django app module path is "introduction.views" based on file_path "introduction/views.py"
from introduction import views


def test_insec_desgine_lab_rejects_non_integer_count(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"count": "not-an-int"}

    # Avoid DB access; only need len(tkts) and ticket list iteration
    mocker.patch.object(views.tickits.objects, "filter", return_value=[])
    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    resp = views.insec_desgine_lab(request)

    # Assert
    render_mock.assert_called_once()
    _, template, context = render_mock.call_args[0]
    assert template == "Lab/A11/a11_lab.html"
    assert context["error"] == "Invalid count value provided"
    assert "tickets" in context
    assert resp is render_mock.return_value


def test_insec_desgine_lab_rejects_count_outside_bounds(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"count": "6"}  # would exceed max 5

    mocker.patch.object(views.tickits.objects, "filter", return_value=[])
    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    resp = views.insec_desgine_lab(request)

    # Assert
    render_mock.assert_called_once()
    _, template, context = render_mock.call_args[0]
    assert template == "Lab/A11/a11_lab.html"
    assert context["error"] == "You can have at most 5 tickits"
    assert resp is render_mock.return_value
