import pytest

# Assumption: Django app module path is "introduction.views" as per source file path.
import introduction.views as views


class _DummyUser:
    def __init__(self, authenticated=True):
        self.is_authenticated = authenticated


class _DummyRequest:
    def __init__(self, method="POST", post=None, user_authenticated=True):
        self.method = method
        self.POST = post or {}
        self.user = _DummyUser(user_authenticated)


def test_insec_desgine_lab_rejects_non_integer_count(mocker):
    # Arrange
    req = _DummyRequest(post={"count": "not-an-int"}, user_authenticated=True)

    # tickits.objects.filter(user=request.user) should return iterable
    mocker.patch.object(views.tickits.objects, "filter", autospec=True, return_value=[])

    render_spy = mocker.patch.object(views, "render", autospec=True)

    # Act
    views.insec_desgine_lab(req)

    # Assert
    render_spy.assert_called_once()
    args, kwargs = render_spy.call_args
    assert args[1] == "Lab/A11/a11_lab.html"
    assert kwargs["context"] == {"error": "Invalid count value provided.", "tickets": []}


def test_insec_desgine_lab_rejects_zero_or_negative_count(mocker):
    # Arrange
    req = _DummyRequest(post={"count": "0"}, user_authenticated=True)

    mocker.patch.object(views.tickits.objects, "filter", autospec=True, return_value=[])
    render_spy = mocker.patch.object(views, "render", autospec=True)

    # Act
    views.insec_desgine_lab(req)

    # Assert
    args, kwargs = render_spy.call_args
    assert args[1] == "Lab/A11/a11_lab.html"
    assert kwargs["context"]["error"] == "You can have atmost 5 tickits"


def test_insec_desgine_lab_rejects_count_exceeding_limit(mocker):
    # Arrange
    req = _DummyRequest(post={"count": "6"}, user_authenticated=True)

    mocker.patch.object(views.tickits.objects, "filter", autospec=True, return_value=[])
    render_spy = mocker.patch.object(views, "render", autospec=True)

    # Act
    views.insec_desgine_lab(req)

    # Assert
    args, kwargs = render_spy.call_args
    assert args[1] == "Lab/A11/a11_lab.html"
    assert kwargs["context"]["error"] == "You can have atmost 5 tickits"
