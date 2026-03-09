import json
import re

import pytest

# Assumption: Django app module path is "introduction.mitre" based on file_path "introduction/mitre.py".
from introduction import mitre


def _make_request(ip_value):
    class _Req:
        method = "POST"
        POST = {"ip": ip_value}

    return _Req()


def test_mitre_lab_17_api_rejects_invalid_ip_or_hostname_returns_400(mocker):
    # Arrange: invalid input containing shell metacharacters/spaces should be rejected before subprocess is invoked
    mocker.patch.object(mitre, "JsonResponse", side_effect=lambda data, status=200: {"data": data, "status": status})
    popen_spy = mocker.patch.object(mitre.subprocess, "Popen")

    request = _make_request("127.0.0.1; whoami")

    # Act
    resp = mitre.mitre_lab_17_api(request)

    # Assert
    assert resp["status"] == 400
    assert resp["data"] == {"error": "Invalid IP or hostname"}
    popen_spy.assert_not_called()


def test_mitre_lab_17_api_uses_shell_false_and_argument_list_for_valid_ip(mocker):
    # Arrange
    mocker.patch.object(mitre, "JsonResponse", side_effect=lambda data, status=200: {"data": data, "status": status})

    # Ensure regex parsing doesn't crash and returns deterministic ports list
    mocker.patch.object(mitre.re, "findall", return_value=["STATE SERVICE\n\n22/tcp open ssh\n"])

    # Mock subprocess.Popen used inside command_out
    process = mocker.Mock()
    process.communicate.return_value = (b"STATE SERVICE\n\n22/tcp open ssh\n", b"")
    popen_mock = mocker.patch.object(mitre.subprocess, "Popen", return_value=process)

    request = _make_request("127.0.0.1")

    # Act
    resp = mitre.mitre_lab_17_api(request)

    # Assert: secure invocation
    popen_mock.assert_called_once()
    args, kwargs = popen_mock.call_args
    assert args[0] == ["nmap", "127.0.0.1"]
    assert kwargs["shell"] is False

    # Assert: response still contains expected keys
    assert resp["status"] == 200
    assert set(resp["data"].keys()) == {"raw_res", "raw_err", "ports"}
    assert resp["data"]["ports"] == ["22/tcp open ssh"]
