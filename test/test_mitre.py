import types

import pytest

# Assumption: Django app module path is "introduction.mitre" as per source file path.
import introduction.mitre as mitre


class _DummyRequest:
    def __init__(self, method="POST", post=None):
        self.method = method
        self.POST = post or {}


def test_mitre_lab_17_api_uses_list_command_and_no_shell_in_popen(mocker):
    # Arrange
    req = _DummyRequest(post={"ip": "127.0.0.1; touch /tmp/pwned"})

    popen_mock = mocker.patch.object(mitre.subprocess, "Popen", autospec=True)
    process = popen_mock.return_value
    process.communicate.return_value = (b"STATE SERVICE\n\n80/tcp open http\n", b"")

    # Act
    resp = mitre.mitre_lab_17_api(req)

    # Assert
    # command_out should call subprocess.Popen without shell=True and with list args
    popen_mock.assert_called_once()
    _, kwargs = popen_mock.call_args
    assert "shell" not in kwargs  # regression: shell=True removed

    cmd_arg = popen_mock.call_args.args[0]
    assert cmd_arg == ["nmap", "127.0.0.1; touch /tmp/pwned"]

    assert resp.status_code == 200
    payload = resp.json()
    assert "ports" in payload
