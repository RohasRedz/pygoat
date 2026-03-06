import json

import pytest

# Assumption: Django is available in the repo test environment.
from django.test import RequestFactory

# Module under test
from introduction import mitre


def test_mitre_lab_17_api_rejects_non_ip_input_with_400_and_does_not_execute_nmap(mocker):
    # Arrange
    rf = RequestFactory()
    req = rf.post("/mitre/17/api", data={"ip": "127.0.0.1; touch /tmp/pwned"})
    mock_command_out = mocker.patch("introduction.mitre.command_out")

    # Act
    resp = mitre.mitre_lab_17_api(req)

    # Assert
    assert resp.status_code == 400
    assert b"Invalid IP address" in resp.content
    mock_command_out.assert_not_called()


def test_mitre_lab_17_api_executes_nmap_with_list_args_and_shell_false_for_valid_ip(mocker):
    # Arrange
    rf = RequestFactory()
    req = rf.post("/mitre/17/api", data={"ip": "127.0.0.1"})

    # Ensure the view can parse ports without depending on nmap output variability
    nmap_stdout = b"STATE SERVICE\n\n22/tcp open ssh\n"
    nmap_stderr = b""
    mocker.patch("introduction.mitre.command_out", return_value=(nmap_stdout, nmap_stderr))

    popen_spy = mocker.patch("introduction.mitre.subprocess.Popen")

    # Act
    resp = mitre.mitre_lab_17_api(req)

    # Assert response is OK and contains parsed ports
    assert resp.status_code == 200
    payload = json.loads(resp.content.decode("utf-8"))
    assert payload["ports"] == ["22/tcp open ssh"]

    # Assert secure subprocess usage: list args and shell=False
    popen_spy.assert_called()
    args, kwargs = popen_spy.call_args
    assert args[0] == ["nmap", "127.0.0.1"]
    assert kwargs.get("shell") is False
