import subprocess
from types import SimpleNamespace

import pytest

# Assumption: Django app module path is "introduction.mitre" based on file_path "introduction/mitre.py".
import introduction.mitre as mitre


def test_mitre_lab_17_api_rejects_invalid_ip_and_does_not_execute_subprocess(mocker):
    # Arrange
    request = SimpleNamespace(method="POST", POST={"ip": "127.0.0.1; rm -rf /"})
    popen_spy = mocker.patch.object(subprocess, "Popen")

    # Act
    response = mitre.mitre_lab_17_api(request)

    # Assert
    assert getattr(response, "status_code", None) == 400
    popen_spy.assert_not_called()


def test_command_out_uses_shell_false(mocker):
    # Arrange
    popen_mock = mocker.patch.object(subprocess, "Popen")
    proc = mocker.Mock()
    proc.communicate.return_value = (b"", b"")
    popen_mock.return_value = proc

    # Act
    mitre.command_out(["nmap", "127.0.0.1"])

    # Assert
    _, kwargs = popen_mock.call_args
    assert kwargs["shell"] is False
