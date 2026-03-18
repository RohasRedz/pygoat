import types

import pytest


# Assumptions:
# - Django is installed and importable in the test environment.
# - The project module path is "introduction.views".


def _make_request(*, method="POST", authenticated=True, post=None):
    user = types.SimpleNamespace(is_authenticated=authenticated)
    return types.SimpleNamespace(method=method, user=user, POST=post or {}, META={}, COOKIES={})


def test_ssrf_lab_strips_directory_traversal_from_blog_filename(mocker):
    from introduction import views

    request = _make_request(post={"blog": "../../etc/passwd"})

    # Ensure open() is called with a path that uses basename only ("passwd")
    open_mock = mocker.patch("builtins.open", mocker.mock_open(read_data="SAFE"))

    render_mock = mocker.patch.object(views, "render", autospec=True)

    views.ssrf_lab(request)

    # open should be called with a filename ending in "passwd" (no traversal segments)
    called_path = open_mock.call_args[0][0]
    assert called_path.endswith("passwd")
    assert ".." not in called_path

    render_mock.assert_called_with(request, "Lab/ssrf/ssrf_lab.html", {"blog": "SAFE"})
