import pytest

# Assumption: tests run with repo root on PYTHONPATH so `introduction` is importable.
import introduction.views as views


def test_ssrf_lab2_blocks_non_whitelisted_domain_and_does_not_call_requests_get(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"url": "http://127.0.0.1:8000/admin"}  # SSRF attempt

    requests_get = mocker.patch.object(views.requests, "get")
    render_spy = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    response = views.ssrf_lab2(request)

    # Assert
    requests_get.assert_not_called()
    render_spy.assert_called_once()
    _, _, context = render_spy.call_args[0][0], render_spy.call_args[0][1], render_spy.call_args[0][2]
    assert context == {"error": "Invalid URL"}
    assert response is render_spy.return_value


def test_ssrf_lab2_allows_whitelisted_domain_and_calls_requests_get(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"url": "http://example.com/path"}

    response_obj = mocker.Mock()
    response_obj.content = b"ok"
    requests_get = mocker.patch.object(views.requests, "get", return_value=response_obj)
    render_spy = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    response = views.ssrf_lab2(request)

    # Assert
    requests_get.assert_called_once_with("http://example.com/path")
    render_spy.assert_called_once()
    assert response is render_spy.return_value
