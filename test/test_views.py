import types

import pytest


def _make_request(blog_value: str):
    user = types.SimpleNamespace(is_authenticated=True)
    return types.SimpleNamespace(method="POST", POST={"blog": blog_value}, user=user)


def test_ssrf_lab_rejects_non_whitelisted_file_key(mocker):
    # Regression test for path traversal fix: only whitelisted keys are allowed.
    from introduction import views

    render_spy = mocker.patch("introduction.views.render", autospec=True)
    open_spy = mocker.patch("builtins.open", autospec=True)

    req = _make_request("../../etc/passwd")
    views.ssrf_lab(req)

    open_spy.assert_not_called()
    render_spy.assert_called()
    assert render_spy.call_args[0][1] == "Lab/ssrf/ssrf_lab.html"
    assert render_spy.call_args[0][2]["blog"] == "Invalid file request"


def test_ssrf_lab_allows_whitelisted_key_and_reads_expected_file(mocker):
    from introduction import views

    render_spy = mocker.patch("introduction.views.render", autospec=True)

    m = mocker.mock_open(read_data="hello")
    open_spy = mocker.patch("builtins.open", m)

    req = _make_request("blog")
    views.ssrf_lab(req)

    open_spy.assert_called_once()
    # Ensure the resolved filename ends with the whitelisted real file.
    assert open_spy.call_args[0][0].endswith("blog.txt")
    render_spy.assert_called()
    assert render_spy.call_args[0][2]["blog"] == "hello"
