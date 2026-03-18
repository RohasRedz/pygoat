import pytest


def test_ssrf_lab2_ignores_user_supplied_url_and_uses_safe_constant(mocker):
    """Regression: ssrf_lab2 must not fetch arbitrary user-supplied URLs (SSRF)."""
    from introduction import views

    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"url": "http://127.0.0.1:8000/admin"}

    response = mocker.Mock()
    response.content = b"OK"
    get_mock = mocker.patch.object(views.requests, "get", return_value=response)

    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    views.ssrf_lab2(request)

    # Assert
    get_mock.assert_called_once_with("https://safe.example.com/resource")
    render_mock.assert_called_with(request, "Lab/ssrf/ssrf_lab2.html", {"response": "OK"})
