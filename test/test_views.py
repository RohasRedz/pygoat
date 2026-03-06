import types

import pytest


def test_insec_desgine_lab_rejects_non_integer_count(mocker):
    # Regression test for input validation fix: non-integer count should be handled.
    from introduction import views

    render_spy = mocker.patch("introduction.views.render", autospec=True)

    # tickits.objects.filter(user=...) returns existing tickets list
    tickits_filter = mocker.patch("introduction.views.tickits.objects.filter", autospec=True)
    tickits_filter.return_value = []

    user = types.SimpleNamespace(is_authenticated=True)
    request = types.SimpleNamespace(method="POST", POST={"count": "not-an-int"}, user=user)

    views.insec_desgine_lab(request)

    render_spy.assert_called()
    assert render_spy.call_args[0][1] == "Lab/A11/a11_lab.html"
    assert render_spy.call_args[0][2]["error"] == "Invalid count value provided."


def test_insec_desgine_lab_rejects_non_positive_count(mocker):
    from introduction import views

    render_spy = mocker.patch("introduction.views.render", autospec=True)
    tickits_filter = mocker.patch("introduction.views.tickits.objects.filter", autospec=True)
    tickits_filter.return_value = []

    user = types.SimpleNamespace(is_authenticated=True)
    request = types.SimpleNamespace(method="POST", POST={"count": "0"}, user=user)

    views.insec_desgine_lab(request)

    render_spy.assert_called()
    assert render_spy.call_args[0][1] == "Lab/A11/a11_lab.html"
    assert render_spy.call_args[0][2]["error"] == "You can have atmost 5 tickits"
