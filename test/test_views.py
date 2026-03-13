import types

import introduction.views as views


def _make_request(user_authenticated: bool, method: str = "POST", blog_value: str = "../etc/passwd"):
    user = types.SimpleNamespace(is_authenticated=user_authenticated)
    post = {"blog": blog_value} if method == "POST" else {}
    return types.SimpleNamespace(user=user, method=method, POST=post)


def test_ssrf_lab_rejects_directory_traversal_and_does_not_open_file(mocker):
    # Arrange
    request = _make_request(user_authenticated=True, method="POST", blog_value="../etc/passwd")

    render_spy = mocker.patch.object(views, "render", return_value="RENDERED")
    open_spy = mocker.patch.object(
        views, "open", side_effect=AssertionError("open() must not be called for invalid paths")
    )

    # Act
    resp = views.ssrf_lab(request)

    # Assert
    assert resp == "RENDERED"
    open_spy.assert_not_called()
    render_spy.assert_called_once()
    args, _kwargs = render_spy.call_args
    assert args[1] == "Lab/ssrf/ssrf_lab.html"
    assert args[2]["blog"] == "Invalid file path provided."


def test_ssrf_lab_rejects_absolute_path_and_does_not_open_file(mocker):
    # Arrange
    request = _make_request(user_authenticated=True, method="POST", blog_value="/etc/passwd")

    render_spy = mocker.patch.object(views, "render", return_value="RENDERED")
    open_spy = mocker.patch.object(
        views, "open", side_effect=AssertionError("open() must not be called for invalid paths")
    )

    # Act
    resp = views.ssrf_lab(request)

    # Assert
    assert resp == "RENDERED"
    open_spy.assert_not_called()
    render_spy.assert_called_once()
    args, _kwargs = render_spy.call_args
    assert args[1] == "Lab/ssrf/ssrf_lab.html"
    assert args[2]["blog"] == "Invalid file path provided."
