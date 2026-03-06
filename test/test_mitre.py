import subprocess

import pytest

# Assumption: Django app module path is "introduction.mitre" based on file_path "introduction/mitre.py".
from introduction import mitre


def test_command_out_does_not_invoke_shell(mocker):
    # Arrange
    popen_mock = mocker.patch("introduction.mitre.subprocess.Popen")
    process = mocker.Mock()
    process.communicate.return_value = (b"ok", b"")
    popen_mock.return_value = process

    # Act
    mitre.command_out(["nmap", "127.0.0.1"])

    # Assert
    popen_mock.assert_called_once()
    _, kwargs = popen_mock.call_args
    assert kwargs.get("shell", None) is None  # regression: shell=True must not be used
    assert kwargs["stdout"] == subprocess.PIPE
    assert kwargs["stderr"] == subprocess.PIPE
