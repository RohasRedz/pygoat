import pytest

# Assumption: repository uses a flat import path where "introduction" is importable in tests.
# If Django settings are required for import, these tests should be run in the project's configured test environment.
from introduction import mitre


def test_mitre_lab_17_api_rejects_invalid_ip_and_does_not_execute_command(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"ip": "127.0.0.1; rm -rf /"}  # command-injection style payload

    popen_spy = mocker.patch.object(mitre.subprocess, "Popen")

    # Act
    response = mitre.mitre_lab_17_api(request)

    # Assert
    assert response.status_code == 400
    popen_spy.assert_not_called()


def test_mitre_lab_17_api_uses_shell_false_and_argv_list(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"ip": "127.0.0.1"}

    process = mocker.Mock()
    # Ensure regex parsing doesn't crash: include the expected "STATE SERVICE" section.
    process.communicate.return_value = (
        b"header\nSTATE SERVICE\n\n80/tcp open http\n",
        b"",
    )
    popen_mock = mocker.patch.object(mitre.subprocess, "Popen", return_value=process)

    # Act
    response = mitre.mitre_lab_17_api(request)

    # Assert
    assert response.status_code == 200
    popen_mock.assert_called_once()
    args, kwargs = popen_mock.call_args
    assert args[0] == ["nmap", "127.0.0.1"]
    assert kwargs.get("shell") is False
