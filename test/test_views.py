import pytest


def test_insec_desgine_lab_rejects_non_integer_ticket_count(mocker):
    """Regression: ticket count must be validated; non-integer input should not create tickets."""
    from introduction import views

    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.user = mocker.Mock()
    request.method = "POST"
    request.POST = {"count": "not-an-int"}

    tkts_qs = mocker.Mock()
    tkts_qs.__iter__ = lambda self: iter([])
    tkts_qs.__len__ = lambda self: 0
    mocker.patch.object(views.tickits.objects, "filter", return_value=tkts_qs)

    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    views.insec_desgine_lab(request)

    # Assert
    render_mock.assert_called_with(
        request,
        "Lab/A11/a11_lab.html",
        {"error": "Invalid input for ticket count", "tickets": []},
    )


def test_insec_desgine_lab_rejects_negative_ticket_count(mocker):
    """Regression: negative ticket count should be rejected."""
    from introduction import views

    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.user = mocker.Mock()
    request.method = "POST"
    request.POST = {"count": "-1"}

    existing = [mocker.Mock(tickit="T1")]
    tkts_qs = mocker.Mock()
    tkts_qs.__iter__ = lambda self: iter(existing)
    tkts_qs.__len__ = lambda self: len(existing)
    mocker.patch.object(views.tickits.objects, "filter", return_value=tkts_qs)

    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    views.insec_desgine_lab(request)

    # Assert
    render_mock.assert_called_with(
        request,
        "Lab/A11/a11_lab.html",
        {"error": "You can have at most 5 tickits", "tickets": ["T1"]},
    )


def test_insec_desgine_lab_rejects_ticket_count_exceeding_limit(mocker):
    """Regression: total tickets must not exceed 5."""
    from introduction import views

    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.user = mocker.Mock()
    request.method = "POST"
    request.POST = {"count": "3"}

    existing = [mocker.Mock(tickit="T1"), mocker.Mock(tickit="T2"), mocker.Mock(tickit="T3")]
    tkts_qs = mocker.Mock()
    tkts_qs.__iter__ = lambda self: iter(existing)
    tkts_qs.__len__ = lambda self: len(existing)
    mocker.patch.object(views.tickits.objects, "filter", return_value=tkts_qs)

    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    views.insec_desgine_lab(request)

    # Assert
    render_mock.assert_called_with(
        request,
        "Lab/A11/a11_lab.html",
        {"error": "You can have at most 5 tickits", "tickets": ["T1", "T2", "T3"]},
    )
