import types

import pytest

# Assumption: tests run with repo root on PYTHONPATH so `introduction` is importable.
import introduction.views as views


def test_ssrf_lab2_rejects_unallowed_domain_and_uses_fallback_url(mocker):
    # Arrange
    request = types.SimpleNamespace(
        method="POST",
        POST={"url": "http://169.254.169.254/latest/meta-data/"},
    )

    requests_get = mocker.patch.object(views.requests, "get")
    requests_get.return_value = types.SimpleNamespace(content=b"blocked")

    render = mocker.patch.object(views, "render", return_value=types.SimpleNamespace(content=b"ok"))

    # Act
    views.ssrf_lab2(request)

    # Assert: regression for SSRF fix - outbound request must not use the attacker-controlled URL
    requests_get.assert_called_once()
    called_url = requests_get.call_args.args[0]
    assert called_url == "https://safe.example.com/default"
    render.assert_called_once()
