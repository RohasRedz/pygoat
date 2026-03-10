import json
from types import SimpleNamespace

import pytest

# Assumption: Django app module path is "introduction.mitre" based on file_path "introduction/mitre.py".
import introduction.mitre as mitre


def _make_request(method="POST", ip="127.0.0.1"):
    return SimpleNamespace(method=method, POST={"ip": ip})


def test_mitre_lab_17_api_rejects_non_ipv4_input_and_does_not_execute_subprocess(mocker):
    # Arrange: attacker-controlled input that previously would have been concatenated into a shell command
    request = _make_request(ip="127.0.0.1; touch /tmp/pwned")

    popen_spy = mocker.patch.object(mitre.subprocess, "Popen")

    # Act
    resp = mitre.mitre_lab_17_api(request)

    # Assert: secure behavior is to reject invalid input early and never invoke subprocess
    assert hasattr(resp, "content")
    payload = json.loads(resp.content.decode("utf-8"))
    assert payload == {"error": "Invalid IP address"}
    popen_spy.assert_not_called()


def test_mitre_lab_17_api_executes_nmap_with_argument_list_and_shell_false(mocker):
    # Arrange
    request = _make_request(ip="127.0.0.1")

    process = mocker.Mock()
    process.communicate.return_value = (
        b"STATE SERVICE\n\n22/tcp open ssh\n",
        b"",
    )
    popen_mock = mocker.patch.object(mitre.subprocess, "Popen", return_value=process)

    # Act
    resp = mitre.mitre_lab_17_api(request)

    # Assert: subprocess is invoked with a list (not a string) and shell=False
    popen_mock.assert_called_once()
    args, kwargs = popen_mock.call_args
    assert args[0] == ["nmap", "127.0.0.1"]
    assert kwargs.get("shell") is False
    assert kwargs.get("stdout") is mitre.subprocess.PIPE
    assert kwargs.get("stderr") is mitre.subprocess.PIPE

    payload = json.loads(resp.content.decode("utf-8"))
    assert "ports" in payload
