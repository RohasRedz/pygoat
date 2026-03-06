import subprocess

import pytest


# Assumption: tests run with repository root on PYTHONPATH so `introduction` is importable.
from introduction import mitre


def test_command_out_uses_shell_false_and_passes_list_to_popen(monkeypatch):
    captured = {}

    class DummyProc:
        def communicate(self):
            return (b"ok", b"")

    def fake_popen(cmd, shell, stdout, stderr):
        captured["cmd"] = cmd
        captured["shell"] = shell
        return DummyProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    out, err = mitre.command_out(["nmap", "127.0.0.1"])

    assert out == b"ok"
    assert err == b""
    assert captured["cmd"] == ["nmap", "127.0.0.1"]
    assert captured["shell"] is False


def test_mitre_lab_17_api_does_not_build_shell_command_string(monkeypatch):
    # Arrange: minimal request stub
    class Req:
        method = "POST"
        POST = {"ip": "127.0.0.1; touch /tmp/pwned"}

    # Provide output matching expected regex parsing in the view
    nmap_output = (
        "header\n"
        "STATE SERVICE\n\n"
        "22/tcp open ssh\n"
        "80/tcp open http\n"
    )

    def fake_command_out(command):
        # Assert inside stub: command must be list, not a concatenated string
        assert isinstance(command, list)
        assert command[0] == "nmap"
        assert command[1] == Req.POST["ip"]
        return (nmap_output.encode(), b"")

    monkeypatch.setattr(mitre, "command_out", fake_command_out)

    # Avoid Django JsonResponse dependency by stubbing it to return the dict payload
    monkeypatch.setattr(mitre, "JsonResponse", lambda payload: payload)

    # Act
    payload = mitre.mitre_lab_17_api(Req())

    # Assert
    assert payload["raw_err"] == ""
    assert "ports" in payload
    assert payload["ports"] == ["22/tcp open ssh", "80/tcp open http"]
