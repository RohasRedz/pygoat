import json
import types

import pytest

import introduction.mitre as mitre


def test_mitre_lab_17_api_uses_subprocess_without_shell_and_argument_list(mocker):
    # Arrange: ensure command_out uses subprocess.Popen with shell=False and list args
    popen_mock = mocker.patch("introduction.mitre.subprocess.Popen")
    process_mock = mocker.Mock()
    process_mock.communicate.return_value = (
        b"STATE SERVICE\n\n22/tcp open ssh\n",
        b"",
    )
    popen_mock.return_value = process_mock

    # Make re.findall deterministic and avoid depending on exact nmap output parsing
    mocker.patch(
        "introduction.mitre.re.findall",
        return_value=["STATE SERVICE\n\n22/tcp open ssh\n"],
    )

    request = types.SimpleNamespace(
        method="POST",
        POST={"ip": "127.0.0.1; touch /tmp/pwned"},
    )

    # Act
    response = mitre.mitre_lab_17_api(request)

    # Assert: subprocess invoked securely (no shell) and with argv list
    popen_mock.assert_called_once()
    called_args, called_kwargs = popen_mock.call_args
    assert called_args[0] == ["nmap", "127.0.0.1; touch /tmp/pwned"]
    assert called_kwargs["shell"] is False

    # Assert: response is JSON and includes expected keys
    payload = json.loads(response.content.decode("utf-8"))
    assert set(payload.keys()) == {"raw_res", "raw_err", "ports"}
