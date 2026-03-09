import types

import pytest

# Assumption: repository uses a typical Django app layout where "introduction" is importable.
from introduction import views


def _make_request(*, method="POST", user_authenticated=True, post_data=None):
    user = types.SimpleNamespace(is_authenticated=user_authenticated)
    req = types.SimpleNamespace(
        method=method,
        user=user,
        POST=post_data or {},
    )
    return req


def test_ssrf_lab_rejects_dotdot_path_traversal_before_open(mocker):
    # Arrange: authenticated POST with traversal payload
    request = _make_request(post_data={"blog": "../secrets.txt"})

    # Ensure we don't touch filesystem; if the fix works, open() is never called.
    open_spy = mocker.patch("builtins.open", autospec=True)
    render_mock = mocker.patch.object(views, "render", autospec=True, return_value=object())

    # Act
    result = views.ssrf_lab(request)

    # Assert: request is handled via exception path and no file open occurs
    assert result is render_mock.return_value
    open_spy.assert_not_called()
    render_mock.assert_called_with(request, "Lab/ssrf/ssrf_lab.html", {"blog": "No blog found"})


def test_ssrf_lab_rejects_absolute_path_before_open(mocker):
    # Arrange: authenticated POST with absolute path payload
    request = _make_request(post_data={"blog": "/etc/passwd"})

    open_spy = mocker.patch("builtins.open", autospec=True)
    render_mock = mocker.patch.object(views, "render", autospec=True, return_value=object())

    # Act
    result = views.ssrf_lab(request)

    # Assert
    assert result is render_mock.return_value
    open_spy.assert_not_called()
    render_mock.assert_called_with(request, "Lab/ssrf/ssrf_lab.html", {"blog": "No blog found"})
