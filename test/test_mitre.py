import re
from types import SimpleNamespace

import pytest


# Assumptions:
# - Django project uses standard pytest discovery.
# - Module under test is importable as introduction.mitre.


def _make_request(ip: str):
    return SimpleNamespace(method="POST", POST={"ip": ip})


def test_mitre_lab_17_api_uses_shell_false_and_list_command(mocker):
    from introduction import mitre

    request = _make_request("127.0.0.1")

    popen_mock = mocker.Mock()
    popen_mock.communicate.return_value = (
        b"STATE SERVICE\n\n22/tcp open ssh\n",
        b"",
    )

    popen_ctor = mocker.patch("introduction.mitre.subprocess.Popen", return_value=popen_mock)
    mocker.patch("introduction.mitre.JsonResponse", side_effect=lambda payload: payload)

    result = mitre.mitre_lab_17_api(request)

    popen_ctor.assert_called_once()
    args, kwargs = popen_ctor.call_args
    assert args[0] == ["nmap", "127.0.0.1"]
    assert kwargs["shell"] is False

    assert result["ports"] == ["22/tcp open ssh"]
