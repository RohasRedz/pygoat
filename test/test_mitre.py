import subprocess

import pytest
from django.http import HttpResponseBadRequest

# Assumption: Django app module path is "introduction.mitre" based on file_path "introduction/mitre.py"
from introduction import mitre


def test_mitre_lab_17_api_rejects_invalid_ip_and_does_not_invoke_subprocess(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"ip": "127.0.0.1; rm -rf /"}  # command-injection style payload

    popen_spy = mocker.patch.object(subprocess, "Popen")

    # Act
    resp = mitre.mitre_lab_17_api(request)

    # Assert
    assert isinstance(resp, HttpResponseBadRequest)
    assert resp.status_code == 400
    popen_spy.assert_not_called()


def test_mitre_lab_17_api_uses_shell_false_and_argument_list(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"ip": "127.0.0.1"}

    popen_mock = mocker.patch.object(subprocess, "Popen")
    proc = popen_mock.return_value
    proc.communicate.return_value = (b"STATE SERVICE\n\n80/tcp open http\n", b"")

    # Avoid brittle regex parsing failures by controlling re.findall output
    mocker.patch.object(mitre.re, "findall", return_value=["STATE SERVICE\n\n80/tcp open http\n"])

    # Act
    resp = mitre.mitre_lab_17_api(request)

    # Assert
    popen_mock.assert_called_once()
    args, kwargs = popen_mock.call_args
    assert args[0] == ["nmap", "127.0.0.1"]
    assert kwargs.get("shell") is False
