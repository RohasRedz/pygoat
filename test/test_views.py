import pytest


def test_ssrf_lab_uses_basename_to_prevent_path_traversal(mocker):
    """Regression: ssrf_lab must strip directory components from user-supplied filename."""
    from introduction import views

    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST = {"blog": "../../etc/passwd"}

    dirname = "/app/introduction"
    mocker.patch.object(views.os.path, "dirname", return_value=dirname)

    # Ensure basename is used and join is called with the sanitized name
    basename_mock = mocker.patch.object(views.os.path, "basename", wraps=views.os.path.basename)
    join_mock = mocker.patch.object(views.os.path, "join", wraps=views.os.path.join)

    # Avoid real file IO
    fake_file = mocker.Mock()
    fake_file.read.return_value = "BLOG_CONTENT"
    mocker.patch.object(views, "open", return_value=fake_file, create=True)

    render_mock = mocker.patch.object(views, "render", return_value=mocker.Mock())

    # Act
    views.ssrf_lab(request)

    # Assert
    basename_mock.assert_called_once_with("../../etc/passwd")
    join_mock.assert_called_with(dirname, "passwd")
    render_mock.assert_called_with(request, "Lab/ssrf/ssrf_lab.html", {"blog": "BLOG_CONTENT"})
