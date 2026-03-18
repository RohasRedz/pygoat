import types

import pytest


# Assumptions:
# - Django is installed and importable in the test environment.
# - The project module path is "introduction.views".


def _make_request(*, method="POST", authenticated=True, post=None, meta=None):
    user = types.SimpleNamespace(is_authenticated=authenticated)
    return types.SimpleNamespace(method=method, user=user, POST=post or {}, META=meta or {}, COOKIES={})


def test_insec_desgine_lab_rejects_non_integer_ticket_count(mocker):
    from introduction import views

    request = _make_request(post={"count": "not-an-int"})

    # tickits.objects.filter(user=request.user) should return an iterable of existing tickets
    tickits_model = mocker.Mock()
    tickits_model.objects.filter.return_value = []
    mocker.patch.object(views, "tickits", tickits_model)

    render_mock = mocker.patch.object(views, "render", autospec=True)

    views.insec_desgine_lab(request)

    render_mock.assert_called_with(
        request,
        "Lab/A11/a11_lab.html",
        {"error": "Invalid input for ticket count", "tickets": []},
    )


def test_insec_desgine_lab_rejects_negative_ticket_count(mocker):
    from introduction import views

    request = _make_request(post={"count": "-1"})

    tickits_model = mocker.Mock()
    tickits_model.objects.filter.return_value = []
    mocker.patch.object(views, "tickits", tickits_model)

    render_mock = mocker.patch.object(views, "render", autospec=True)

    views.insec_desgine_lab(request)

    render_mock.assert_called_with(
        request,
        "Lab/A11/a11_lab.html",
        {"error": "You can have at most 5 tickits", "tickets": []},
    )
