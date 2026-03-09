import pytest

# Assumption: repository uses "introduction" as a top-level Python package.
from introduction import mitre


def test_command_out_does_not_invoke_shell(mocker):
    # Arrange
    popen = mocker.patch("introduction.mitre.subprocess.Popen", autospec=True)
    proc = popen.return_value
    proc.communicate.return_value = (b"ok", b"")

    # Act
    mitre.command_out(["nmap", "127.0.0.1"])

    # Assert: secure behavior after fix - shell=True is not used
    _, kwargs = popen.call_args
    assert "shell" not in kwargs or kwargs["shell"] is False


def test_mitre_lab_17_api_builds_argv_list_for_nmap(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"ip": "127.0.0.1"}

    # Make command_out return output that matches the regex used by the handler
    sample = (
        "STATE SERVICE\n\n"
        "22/tcp open ssh\n"
        "80/tcp open http\n"
    )
    cmd_out = mocker.patch("introduction.mitre.command_out", autospec=True, return_value=(sample.encode(), b""))
    json_response = mocker.patch("introduction.mitre.JsonResponse", autospec=True, side_effect=lambda payload: payload)

    # Act
    payload = mitre.mitre_lab_17_api(request)

    # Assert: previously vulnerable behavior (string command) is no longer used
    cmd_out.assert_called_once()
    called_command = cmd_out.call_args.args[0]
    assert called_command == ["nmap", "127.0.0.1"]
    assert "ports" in payload
    assert payload["ports"] == ["22/tcp open ssh", "80/tcp open http"]
    json_response.assert_called_once()
