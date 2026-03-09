import types

import pytest

# Assumption: tests run with repo root on PYTHONPATH so `introduction` is importable.
import introduction.mitre as mitre


def test_mitre_lab_17_api_uses_subprocess_without_shell(mocker):
    # Arrange
    request = types.SimpleNamespace(
        method="POST",
        POST={"ip": "127.0.0.1; touch /tmp/pwned"},
    )

    popen_mock = mocker.Mock()
    popen_mock.communicate.return_value = (
        b"STATE SERVICE\n\n80/tcp open http\n",
        b"",
    )
    popen_ctor = mocker.patch.object(mitre.subprocess, "Popen", return_value=popen_mock)

    # Act
    resp = mitre.mitre_lab_17_api(request)

    # Assert: regression for command injection fix - shell must be disabled and args must be a list
    popen_ctor.assert_called_once()
    args, kwargs = popen_ctor.call_args
    assert args[0] == ["nmap", "127.0.0.1; touch /tmp/pwned"]
    assert kwargs["shell"] is False
    assert kwargs["stdout"] is mitre.subprocess.PIPE
    assert kwargs["stderr"] is mitre.subprocess.PIPE

    # Ensure handler still returns a JsonResponse-like object
    assert hasattr(resp, "content")
