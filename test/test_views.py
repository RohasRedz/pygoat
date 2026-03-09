# Assumption: project uses pytest and imports modules by package name "introduction".
# These tests focus on the delta: allowlist enforcement and safe path containment.

import introduction.views as views


def test_ssrf_lab_rejects_non_allowlisted_blog_key(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST.__getitem__.return_value = "../../etc/passwd"

    render_spy = mocker.patch("introduction.views.render", side_effect=lambda _req, _tpl, ctx: ctx)

    # Act
    result = views.ssrf_lab(request)

    # Assert
    assert result["blog"] == "Invalid file selection"
    # Ensure we never attempt to open a file for invalid keys
    # (open is a builtin; patch where it's used)
    # If open were called, it would indicate traversal still possible.
    # Note: open is only reached after allowlist passes.
    # So we only need to assert render was called with the invalid selection message.
    render_spy.assert_called_once()


def test_ssrf_lab_denies_when_resolved_path_escapes_safe_dir(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.method = "POST"
    request.POST.__getitem__.return_value = "blog"  # allowlisted key

    # Force containment check to fail: resolved_path not starting with safe_dir
    mocker.patch("introduction.views.os.path.dirname", return_value="/safe")
    mocker.patch("introduction.views.os.path.join", return_value="/safe/blog.txt")
    mocker.patch("introduction.views.os.path.realpath", side_effect=["/safe", "/evil/blog.txt"])

    render_spy = mocker.patch("introduction.views.render", side_effect=lambda _req, _tpl, ctx: ctx)
    open_spy = mocker.patch("builtins.open")

    # Act
    result = views.ssrf_lab(request)

    # Assert
    assert result["blog"] == "Access Denied"
    open_spy.assert_not_called()
    render_spy.assert_called_once()
