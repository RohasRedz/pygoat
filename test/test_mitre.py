import subprocess

import pytest

# Assumption: tests run with repo root on PYTHONPATH so "introduction" is importable.
from introduction import mitre


def test_command_out_does_not_invoke_shell(mocker):
    # Arrange
    popen_spy = mocker.patch("introduction.mitre.subprocess.Popen")
    proc = popen_spy.return_value
    proc.communicate.return_value = (b"ok", b"")

    # Act
    out, err = mitre.command_out(["nmap", "127.0.0.1"])

    # Assert
    assert (out, err) == (b"ok", b"")
    popen_spy.assert_called_once()
    _, kwargs = popen_spy.call_args
    assert kwargs.get("shell") is False
