import types
import subprocess

import pytest

# Assumption: tests run with repo root on PYTHONPATH so `introduction` is importable.
import introduction.mitre as mitre


def test_command_out_uses_shell_false_and_does_not_invoke_shell(mocker):
    # Arrange
    popen_spy = mocker.patch.object(subprocess, "Popen", autospec=True)
    proc = popen_spy.return_value
    proc.communicate.return_value = (b"ok", b"")

    # Act
    out, err = mitre.command_out(["nmap", "127.0.0.1"])

    # Assert
    assert (out, err) == (b"ok", b"")
    popen_spy.assert_called_once()
    _, kwargs = popen_spy.call_args
    assert kwargs["shell"] is False


def test_mitre_lab_17_api_builds_argument_list_not_command_string(mocker):
    # Arrange
    # Patch command_out to capture the command passed to it.
    command_out_mock = mocker.patch.object(mitre, "command_out", autospec=True, return_value=(b"", b""))

    # Avoid regex parsing errors by returning a minimal response that matches the expected pattern.
    fake_nmap_output = "STATE SERVICE\n\n22/tcp open ssh\n"
    command_out_mock.return_value = (fake_nmap_output.encode("utf-8"), b"")

    # Replace JsonResponse with a simple passthrough so we don't need Django configured.
    mocker.patch.object(mitre, "JsonResponse", autospec=True, side_effect=lambda payload: payload)

    request = types.SimpleNamespace(
        method="POST",
        POST={"ip": "127.0.0.1; touch /tmp/pwned"},
    )

    # Act
    payload = mitre.mitre_lab_17_api(request)

    # Assert
    assert command_out_mock.call_count == 1
    passed_command = command_out_mock.call_args.args[0]
    assert passed_command == ["nmap", "127.0.0.1; touch /tmp/pwned"]
    assert isinstance(passed_command, list)
    assert payload["raw_err"] == ""
