from types import SimpleNamespace

# Assumption: Django app module path is "introduction.views" based on file_path "introduction/views.py".
import introduction.views as views


def test_ssrf_lab2_ignores_user_supplied_url_and_uses_safe_base_url(mocker):
    # Arrange
    request = SimpleNamespace(
        method="POST",
        POST={"url": "http://169.254.169.254/latest/meta-data/"},
    )

    # Patch settings used inside the function (from django.conf import settings)
    settings_obj = SimpleNamespace(SAFE_BASE_URL="https://example.com/safe")
    mocker.patch("django.conf.settings", settings_obj, create=True)

    requests_get = mocker.patch.object(views.requests, "get")
    requests_get.return_value = SimpleNamespace(content=b"ok")

    render_mock = mocker.patch.object(views, "render", return_value=SimpleNamespace(status_code=200))

    # Act
    views.ssrf_lab2(request)

    # Assert
    requests_get.assert_called_once_with("https://example.com/safe")
    assert render_mock.call_args[0][1] == "Lab/ssrf/ssrf_lab2.html"
