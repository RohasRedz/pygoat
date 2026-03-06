import subprocess

import pytest


# Assumptions:
# - Django is available in the test environment.
# - Module path is "introduction.mitre" as implied by file_path.
from introduction import mitre


def _make_request(method="POST", post=None, cookies=None):
    class _Req:
        def __init__(self):
            self.method = method
            self.POST = post or {}
            self.COOKIES = cookies or {}

    return _Req()


def test_mitre_lab_17_api_uses_shell_false_and_argument_list(mocker):
    # Arrange
    req = _make_request(method="POST", post={"ip": "127.0.0.1"})

    popen_mock = mocker.Mock()
    process_mock = mocker.Mock()
    process_mock.communicate.return_value = (b"STATE SERVICE\n\n22/tcp open ssh\n", b"")
    popen_mock.return_value = process_mock

    mocker.patch.object(mitre.subprocess, "Popen", popen_mock)

    # Avoid depending on Django JsonResponse internals; just ensure call path completes.
    mocker.patch.object(mitre, "JsonResponse", lambda payload: payload)

    # Act
    result = mitre.mitre_lab_17_api(req)

    # Assert
    popen_mock.assert_called_once()
    args, kwargs = popen_mock.call_args
    assert args[0] == ["nmap", "127.0.0.1"]
    assert kwargs.get("shell") is False
    assert "ports" in result
    assert result["ports"] == ["22/tcp open ssh"]
