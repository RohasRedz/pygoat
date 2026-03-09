import importlib
import types

import pytest


def _import_mitre_module():
    # Assumption: Django app module path is "introduction.mitre" based on file_path.
    return importlib.import_module("introduction.mitre")


def test_mitre_lab_17_api_rejects_non_ip_input_and_does_not_execute_command(mocker):
    """
    Delta test for command injection fix:
    - Now validates IP using ipaddress.ip_address and returns 400 on invalid input.
    - Ensures command execution path is not reached for invalid input.
    """
    mitre = _import_mitre_module()

    # Arrange
    request = types.SimpleNamespace(method="POST", POST={"ip": "127.0.0.1; rm -rf /"})

    command_out_mock = mocker.patch.object(mitre, "command_out", autospec=True)
    json_response_mock = mocker.patch.object(
        mitre, "JsonResponse", side_effect=lambda payload, status=200: {"payload": payload, "status": status}
    )

    # Act
    resp = mitre.mitre_lab_17_api(request)

    # Assert
    command_out_mock.assert_not_called()
    assert resp["status"] == 400
    assert resp["payload"] == {"error": "Invalid IP address provided"}
    json_response_mock.assert_called()
