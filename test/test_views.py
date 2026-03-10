import pytest

# Assumption: project uses a Django app module named "introduction" and the view is importable as below.
from introduction import views


def _make_request(mocker, *, blog_value):
    request = mocker.Mock()
    request.user = mocker.Mock(is_authenticated=True)
    request.method = "POST"
    request.POST = {"blog": blog_value}
    return request


def test_ssrf_lab_rejects_absolute_path_before_open(mocker):
    # Arrange
    request = _make_request(mocker, blog_value="/etc/passwd")
    render_spy = mocker.patch.object(views, "render", autospec=True, return_value="RENDERED")
    open_spy = mocker.patch("builtins.open", autospec=True)

    # Act
    result = views.ssrf_lab(request)

    # Assert
    assert result == "RENDERED"
    open_spy.assert_not_called()
    render_spy.assert_called_with(request, "Lab/ssrf/ssrf_lab.html", {"blog": "Invalid file path provided"})


def test_ssrf_lab_rejects_parent_directory_traversal_before_open(mocker):
    # Arrange
    request = _make_request(mocker, blog_value="../secrets.txt")
    render_spy = mocker.patch.object(views, "render", autospec=True, return_value="RENDERED")
    open_spy = mocker.patch("builtins.open", autospec=True)

    # Act
    result = views.ssrf_lab(request)

    # Assert
    assert result == "RENDERED"
    open_spy.assert_not_called()
    render_spy.assert_called_with(request, "Lab/ssrf/ssrf_lab.html", {"blog": "Invalid file path provided"})
