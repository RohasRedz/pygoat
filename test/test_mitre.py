import subprocess

import pytest


# Assumption: tests run with Django app importable; we unit-test by mocking subprocess.Popen.
from introduction import mitre


def test_command_out_uses_shell_false_and_does_not_invoke_shell(mocker):
    popen_mock = mocker.patch("introduction.mitre.subprocess.Popen")
    proc = mocker.Mock()
    proc.communicate.return_value = (b"ok", b"")
    popen_mock.return_value = proc

    mitre.command_out(["nmap", "127.0.0.1"])

    popen_mock.assert_called_once()
    _, kwargs = popen_mock.call_args
    assert kwargs["shell"] is False


def test_mitre_lab_17_api_builds_argument_list_not_shell_string(mocker):
    request = mocker.Mock()
    request.method = "POST"
    request.POST.get.return_value = "127.0.0.1; echo pwned"

    command_out_mock = mocker.patch("introduction.mitre.command_out", return_value=(b"STATE SERVICE\n\n80/tcp open http\n", b""))
    mocker.patch("introduction.mitre.re.findall", return_value=["STATE SERVICE\n\n80/tcp open http\n"])

    mitre.mitre_lab_17_api(request)

    (cmd,), _ = command_out_mock.call_args
    assert cmd == ["nmap", "127.0.0.1; echo pwned"]
