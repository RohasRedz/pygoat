import re
import types

import pytest


def _make_request(method="POST", post=None, body=b"", authenticated=True):
    user = types.SimpleNamespace(is_authenticated=authenticated)
    return types.SimpleNamespace(method=method, POST=post or {}, body=body, user=user)


def test_mitre_lab_17_api_uses_subprocess_without_shell_and_without_string_command(monkeypatch):
    # Import inside test to ensure monkeypatching affects module-level references
    import introduction.mitre as mitre

    called = {}

    def fake_popen(cmd, shell, stdout, stderr):
        called["cmd"] = cmd
        called["shell"] = shell

        class _Proc:
            def communicate(self_inner):
                # Minimal nmap-like output matching the regex used in the view
                out = b"STATE SERVICE\n\n22/tcp open ssh\n"
                return out, b""

        return _Proc()

    monkeypatch.setattr(mitre.subprocess, "Popen", fake_popen)

    req = _make_request(post={"ip": "127.0.0.1; echo pwned"})
    resp = mitre.mitre_lab_17_api(req)

    assert called["shell"] is False
    assert isinstance(called["cmd"], list)
    assert called["cmd"][0] == "nmap"
    assert called["cmd"][1] == "127.0.0.1; echo pwned"

    # Ensure response is JSON and ports were parsed
    assert hasattr(resp, "content")
    assert b"ports" in resp.content
