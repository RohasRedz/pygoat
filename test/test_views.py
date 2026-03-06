from types import SimpleNamespace

# Assumption: Django app module path is "introduction.views" based on file_path "introduction/views.py".
import introduction.views as views


def test_ssrf_lab_rejects_absolute_path_blog_parameter(mocker):
    # Arrange
    request = SimpleNamespace(
        user=SimpleNamespace(is_authenticated=True),
        method="POST",
        POST={"blog": "/etc/passwd"},
    )
    open_mock = mocker.patch("builtins.open")
    render_mock = mocker.patch.object(views, "render", return_value=SimpleNamespace(status_code=200))

    # Act
    views.ssrf_lab(request)

    # Assert
    open_mock.assert_not_called()
    # Ensure the new secure behavior returns the "Invalid file parameter" message
    assert render_mock.call_args[0][1] == "Lab/ssrf/ssrf_lab.html"
    assert render_mock.call_args[0][2]["blog"] == "Invalid file parameter"
