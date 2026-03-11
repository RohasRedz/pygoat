import json
import types

import pytest

import introduction.mitre as mitre


def test_command_out_does_not_use_shell_and_passes_args_list(mocker):
    # Arrange
    popen_mock = mocker.Mock()
    popen_mock.communicate.return_value = (b"ok", b"")
    popen_ctor = mocker.patch.object(mitre.subprocess, "Popen", return_value=popen_mock)

    # Act
    mitre.command_out(["nmap", "127.0.0.1"])

    # Assert
    # Regression for vuln fix: ensure shell=True is not used and args are passed as a list
    _, kwargs = popen_ctor.call_args
    assert "shell" not in kwargs
    assert kwargs["stdout"] == mitre.subprocess.PIPE
    assert kwargs["stderr"] == mitre.subprocess.PIPE


def test_mitre_lab_17_api_builds_subprocess_command_as_list_not_string(mocker):
    # Arrange
    # Patch command_out to avoid running subprocess and to ensure it receives a list command
    def _fake_command_out(cmd):
        assert isinstance(cmd, list)
        assert cmd[0] == "nmap"
        return (b"STATE SERVICE\n\n22/tcp open ssh\n", b"")

    mocker.patch.object(mitre, "command_out", side_effect=_fake_command_out)

    # Avoid brittle regex parsing failures by controlling re.findall output
    mocker.patch.object(mitre.re, "findall", return_value=["STATE SERVICE\n\n22/tcp open ssh\n"])

    request = types.SimpleNamespace(method="POST", POST={"ip": "127.0.0.1; rm -rf /"})

    # Act
    resp = mitre.mitre_lab_17_api(request)

    # Assert
    assert resp.status_code == 200
    payload = json.loads(resp.content.decode("utf-8"))
    assert set(payload.keys()) == {"raw_res", "raw_err", "ports"}
