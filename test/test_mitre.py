import types

import pytest


def test_mitre_lab_17_api_uses_subprocess_without_shell_and_list_command(mocker):
    # Regression test for command injection fix: subprocess should be invoked without shell=True
    # and with a list command ["nmap", ip] rather than a concatenated string.
    from introduction import mitre

    popen_spy = mocker.patch("introduction.mitre.subprocess.Popen", autospec=True)

    # Fake process output to satisfy downstream parsing.
    fake_proc = mocker.Mock()
    fake_proc.communicate.return_value = (
        b"STATE SERVICE\n\n22/tcp open ssh\n",
        b"",
    )
    popen_spy.return_value = fake_proc

    # Avoid brittle regex parsing failures; focus on command construction.
    mocker.patch("introduction.mitre.re.findall", return_value=["STATE SERVICE\n\n22/tcp open ssh\n\n"])

    user = types.SimpleNamespace(is_authenticated=True)
    request = types.SimpleNamespace(method="POST", POST={"ip": "127.0.0.1"}, user=user)

    mitre.mitre_lab_17_api(request)

    popen_spy.assert_called_once()
    args, kwargs = popen_spy.call_args
    assert args[0] == ["nmap", "127.0.0.1"]
    assert kwargs.get("shell") is None
