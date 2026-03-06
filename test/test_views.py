import introduction.views as views


def test_insec_desgine_lab_rejects_non_integer_count(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST.get.side_effect = lambda k, default=None: {"count": "not-an-int"}.get(k, default)
    request.user = mocker.Mock()

    tkts_qs = []
    mocker.patch.object(views.tickits.objects, "filter", return_value=tkts_qs)

    render_spy = mocker.patch.object(views, "render", return_value="rendered")

    # Act
    resp = views.insec_desgine_lab(request)

    # Assert
    assert resp == "rendered"
    render_spy.assert_called()
    _, template, context = render_spy.call_args[0]
    assert template == "Lab/A11/a11_lab.html"
    assert context["error"] == "Invalid count value"
    assert "tickets" in context


def test_insec_desgine_lab_rejects_out_of_range_count(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST.get.side_effect = lambda k, default=None: {"count": "10"}.get(k, default)
    request.user = mocker.Mock()

    # Existing tickets length makes max allowed (5 - len(tkts)) smaller
    tkts_qs = [mocker.Mock(tickit="A"), mocker.Mock(tickit="B"), mocker.Mock(tickit="C"), mocker.Mock(tickit="D")]
    mocker.patch.object(views.tickits.objects, "filter", return_value=tkts_qs)

    render_spy = mocker.patch.object(views, "render", return_value="rendered")

    # Act
    resp = views.insec_desgine_lab(request)

    # Assert
    assert resp == "rendered"
    _, template, context = render_spy.call_args[0]
    assert template == "Lab/A11/a11_lab.html"
    assert context["error"] == "Invalid count value"
