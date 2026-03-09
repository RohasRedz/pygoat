import json
from types import SimpleNamespace

import pytest

# Assumption: tests run with repo root on PYTHONPATH so "introduction" is importable.
import introduction.mitre as mitre


def _make_request(ip: str):
    return SimpleNamespace(method="POST", POST={"ip": ip})


def test_mitre_lab_17_api_rejects_non_ipv4_input_and_does_not_invoke_subprocess(monkeypatch):
    # Arrange
    called = {"count": 0}

    def _fake_command_out(_command):
        called["count"] += 1
        return (b"", b"")

    monkeypatch.setattr(mitre, "command_out", _fake_command_out)

    # Act
    resp = mitre.mitre_lab_17_api(_make_request("127.0.0.1; touch /tmp/pwned"))

    # Assert
    assert called["count"] == 0
    assert resp.status_code == 200
    payload = json.loads(resp.content.decode("utf-8"))
    assert payload == {"error": "Invalid IP address"}


def test_mitre_lab_17_api_uses_list_command_not_shell_string(monkeypatch):
    # Arrange
    captured = {}

    def _fake_command_out(command):
        captured["command"] = command
        # Provide minimal output that satisfies the regex parsing in the view.
        return (b"STATE SERVICE\n\n22/tcp open ssh\n\n", b"")

    monkeypatch.setattr(mitre, "command_out", _fake_command_out)

    # Act
    resp = mitre.mitre_lab_17_api(_make_request("127.0.0.1"))

    # Assert
    assert resp.status_code == 200
    assert captured["command"] == ["nmap", "127.0.0.1"]
