# Assumption: project root is on PYTHONPATH so `import introduction.mitre` works in tests.

import json
import types

import pytest

import introduction.mitre as mitre


def _make_request(ip: str):
    return types.SimpleNamespace(method="POST", POST={"ip": ip})


def test_mitre_lab_17_api_rejects_non_ipv4_and_does_not_execute_subprocess(monkeypatch):
    # Arrange
    called = {"count": 0}

    def _popen_should_not_be_called(*args, **kwargs):
        called["count"] += 1
        raise AssertionError("subprocess.Popen must not be called for invalid IP input")

    monkeypatch.setattr(mitre.subprocess, "Popen", _popen_should_not_be_called)

    # Act
    resp = mitre.mitre_lab_17_api(_make_request("127.0.0.1; whoami"))

    # Assert
    assert resp.status_code == 400
    payload = json.loads(resp.content.decode("utf-8"))
    assert payload["error"] == "Invalid IP address"
    assert called["count"] == 0


def test_mitre_lab_17_api_uses_arg_list_without_shell_true(monkeypatch):
    # Arrange
    popen_args = {}

    class _FakeProc:
        def communicate(self):
            # minimal output to satisfy parsing logic
            return (b"STATE SERVICE\n\n22/tcp open ssh\n", b"")

    def _fake_popen(args, **kwargs):
        popen_args["args"] = args
        popen_args["kwargs"] = kwargs
        return _FakeProc()

    monkeypatch.setattr(mitre.subprocess, "Popen", _fake_popen)

    # Act
    resp = mitre.mitre_lab_17_api(_make_request("127.0.0.1"))

    # Assert
    assert resp.status_code == 200
    assert popen_args["args"] == ["nmap", "127.0.0.1"]
    assert popen_args["kwargs"].get("shell") is None  # shell=True must not be used
