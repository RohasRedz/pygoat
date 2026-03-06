import introduction.views as views


def test_ssrf_lab2_uses_safe_url_from_settings_instead_of_user_input(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"url": "http://169.254.169.254/latest/meta-data"}  # attacker-controlled input

    # Ensure SAFE_URL is used
    mocker.patch.object(views.settings, "SAFE_URL", "http://safe.example.com/api", create=True)

    requests_get_spy = mocker.patch.object(views.requests, "get", return_value=mocker.Mock(content=b"ok"))
    render_spy = mocker.patch.object(views, "render", return_value="rendered")

    # Act
    resp = views.ssrf_lab2(request)

    # Assert
    assert resp == "rendered"
    requests_get_spy.assert_called_once_with("http://safe.example.com/api")
    render_spy.assert_called()
