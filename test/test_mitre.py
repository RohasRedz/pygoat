import json
import types

import pytest

import introduction.mitre as mitre


def test_mitre_lab_17_api_uses_subprocess_without_shell_and_argv_list(mocker):
    # Arrange: prevent auth decorator from interfering (it is imported into this module)
    mocker.patch.object(mitre, "authentication_decorator", lambda f: f)

    # Spy on subprocess.Popen used by command_out()
    popen_mock = mocker.patch.object(mitre.subprocess, "Popen")

    process = types.SimpleNamespace()
    process.communicate = mocker.Mock(return_value=(b"STATE SERVICE\n\n22/tcp open ssh\n", b""))
    popen_mock.return_value = process

    # Stub request with POST.get('ip') returning an injection-like payload
    class _Post:
        def get(self, key):
            assert key == "ip"
            return "127.0.0.1; echo pwned"

    request = types.SimpleNamespace(method="POST", POST=_Post())

    # Avoid Django dependency in unit test: stub JsonResponse to just return the payload
    mocker.patch.object(mitre, "JsonResponse", lambda payload: payload)

    # Act
    resp = mitre.mitre_lab_17_api(request)

    # Assert: secure behavior - no shell, argv list passed to Popen
    popen_mock.assert_called_once()
    args, kwargs = popen_mock.call_args
    assert args[0] == ["nmap", "127.0.0.1; echo pwned"]
    assert kwargs["shell"] is False
    assert "stdout" in kwargs and "stderr" in kwargs

    # And endpoint still returns expected keys
    assert set(resp.keys()) == {"raw_res", "raw_err", "ports"}
