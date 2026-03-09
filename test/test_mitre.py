import importlib

import pytest


def test_mitre_lab_17_api_rejects_non_ipv4_format_and_does_not_execute_command(mocker):
    # Arrange
    mitre = importlib.import_module("introduction.mitre")

    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"ip": "127.0.0.1; rm -rf /"}  # previously would be concatenated into a shell command

    popen_spy = mocker.patch.object(mitre.subprocess, "Popen")

    # Act
    response = mitre.mitre_lab_17_api(request)

    # Assert
    assert getattr(response, "status_code", None) == 400
    popen_spy.assert_not_called()


def test_mitre_lab_17_api_executes_nmap_with_shell_disabled_and_argument_list(mocker):
    # Arrange
    mitre = importlib.import_module("introduction.mitre")

    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"ip": "127.0.0.1"}

    # Ensure we don't actually spawn a process; also verify secure invocation.
    popen_mock = mocker.patch.object(mitre.subprocess, "Popen")
    process_mock = mocker.Mock()
    process_mock.communicate.return_value = (
        b"STATE SERVICE\n\n22/tcp open ssh\n",
        b"",
    )
    popen_mock.return_value = process_mock

    # Act
    response = mitre.mitre_lab_17_api(request)

    # Assert: secure subprocess invocation
    popen_mock.assert_called_once()
    called_args, called_kwargs = popen_mock.call_args
    assert called_args[0] == ["nmap", "127.0.0.1"]
    assert called_kwargs.get("shell") is False

    # Assert: still returns JSON response
    assert getattr(response, "status_code", 200) == 200
