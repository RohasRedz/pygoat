import types

import pytest

# Assumption: project uses a src/ layout where "introduction" is importable in tests.
# If not, adjust PYTHONPATH in test runner configuration.
from introduction import mitre


def test_mitre_lab_17_api_rejects_non_ipv4_and_does_not_invoke_nmap(mocker):
    # Arrange
    request = types.SimpleNamespace(method="POST", POST={"ip": "127.0.0.1; rm -rf /"})
    command_out_spy = mocker.spy(mitre, "command_out")

    # Act
    response = mitre.mitre_lab_17_api(request)

    # Assert
    assert getattr(response, "status_code", None) == 400
    # Ensure we didn't attempt to execute anything when input is invalid
    assert command_out_spy.call_count == 0


def test_mitre_lab_17_api_uses_subprocess_arg_list_not_shell_string(mocker):
    # Arrange
    request = types.SimpleNamespace(method="POST", POST={"ip": "127.0.0.1"})
    # Provide output that satisfies the regex extraction in the view
    mocker.patch.object(
        mitre,
        "command_out",
        autospec=True,
        return_value=(b"STATE SERVICE\n\n80/tcp open http\n", b""),
    )

    # Act
    response = mitre.mitre_lab_17_api(request)

    # Assert
    assert getattr(response, "status_code", 200) == 200
    mitre.command_out.assert_called_once()
    called_command = mitre.command_out.call_args[0][0]
    assert called_command == ["nmap", "127.0.0.1"]
