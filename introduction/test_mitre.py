# File: introduction/test_mitre.py
# NOTE: Assumes pytest and Django's test environment when running these tests.
# These tests focus only on the changed security behavior:
# - Safe eval with restricted expressions in mitre_lab_25_api.
# - Safe nmap command execution without shell=True and with input validation in mitre_lab_17_api.
# TODO: Configure Django settings for tests (DJANGO_SETTINGS_MODULE) in the test runner.

import json
import re

import pytest
from django.http import HttpRequest
from django.test import RequestFactory
from django.urls import reverse

from introduction import mitre as mitre_module


@pytest.fixture
def rf():
    return RequestFactory()


def test_mitre_lab_25_api_allows_simple_arithmetic(rf):
    """
    Delta test:
    - Before: eval(expression) executed arbitrary Python from user input.
    - After: expression is restricted by a regex and eval is run with no builtins.
    This test confirms that benign arithmetic expressions still work.
    """
    request = rf.post("/mitre/25/api", data={"expression": "1 + 2 * 3"})
    response = mitre_module.mitre_lab_25_api(request)

    assert response.status_code == 200
    data = json.loads(response.content.decode("utf-8"))
    assert data["result"] == 7


def test_mitre_lab_25_api_rejects_dangerous_expression(rf, monkeypatch):
    """
    Delta test:
    Confirms that obviously dangerous expressions such as __import__('os').system('id')
    are rejected by the new validation logic and do not get executed.
    """
    dangerous = "__import__('os').system('id')"
    request = rf.post("/mitre/25/api", data={"expression": dangerous})
    response = mitre_module.mitre_lab_25_api(request)

    # Should respond with an error status, not 200 OK.
    assert response.status_code >= 400
    body = response.content.decode("utf-8").lower()
    assert "invalid expression" in body or "error evaluating expression" in body


def test_mitre_lab_17_api_rejects_invalid_ip(rf):
    """
    Delta test:
    - Before: command_out used 'nmap ' + ip with shell=True, allowing command injection.
    - After: command_out_safe validates IP/host and uses subprocess without shell=True.
    This test verifies that an obviously invalid or malicious IP string is rejected.
    """
    request = rf.post("/mitre/17/api", data={"ip": "127.0.0.1;rm -rf /"})
    response = mitre_module.mitre_lab_17_api(request)

    assert response.status_code >= 400
    body = response.content.decode("utf-8").lower()
    assert "invalid ip" in body or "error" in body


def test_mitre_lab_17_api_accepts_simple_hostname(monkeypatch, rf):
    """
    Delta test:
    For a simple, valid hostname, the new command_out_safe should be invoked
    with a safe subprocess call (shell=False), and the view should return
    a JSON structure without raising validation errors.
    We mock subprocess.Popen indirectly via the helper to avoid real nmap calls.
    """

    class FakeProcess:
        def communicate(self):
            # Minimal fake nmap output that still matches the parsing regex
            output = (
                "Starting Nmap 7.80 ( https://nmap.org )\n"
                "Nmap scan report for example.com (93.184.216.34)\n"
                "Host is up (0.030s latency).\n"
                "PORT    STATE SERVICE\n"
                "22/tcp  open  ssh\n"
                "80/tcp  open  http\n\n"
            ).encode("utf-8")
            return output, b""

    def fake_command_out_safe(ip: str):
        return FakeProcess().communicate()

    monkeypatch.setattr(mitre_module, "command_out_safe", fake_command_out_safe)

    request = rf.post("/mitre/17/api", data={"ip": "example.com"})
    response = mitre_module.mitre_lab_17_api(request)

    assert response.status_code == 200
    data = json.loads(response.content.decode("utf-8"))
    # Should parse ports from the fake output
    assert "ports" in data
    assert any("ssh" in p or "http" in p for p in data["ports"])
