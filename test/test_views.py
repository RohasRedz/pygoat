from types import SimpleNamespace

import pytest


# Assumptions:
# - Module under test is importable as introduction.views.


def _make_authenticated_request(blog_value: str):
    user = SimpleNamespace(is_authenticated=True)
    return SimpleNamespace(method="POST", POST={"blog": blog_value}, user=user)


def test_ssrf_lab_rejects_directory_traversal_and_does_not_open_file(mocker):
    from introduction import views

    request = _make_authenticated_request("../secrets.txt")

    open_mock = mocker.patch("builtins.open", mocker.mock_open(read_data="SHOULD_NOT_READ"))
    render_mock = mocker.patch("introduction.views.render", side_effect=lambda req, tpl, ctx=None: {"tpl": tpl, "ctx": ctx})

    result = views.ssrf_lab(request)

    # Directory traversal should be rejected and handled by the except branch.
    assert result["ctx"]["blog"] == "No blog found"
    open_mock.assert_not_called()
    assert render_mock.call_args[0][1] == "Lab/ssrf/ssrf_lab.html"
