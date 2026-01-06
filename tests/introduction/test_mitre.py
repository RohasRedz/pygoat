from unittest import mock

import pytest
from introduction import mitre as mitre_module


@pytest.fixture
def client():
    app = mitre_module.app
    app.config.update({"TESTING": True})
    with app.test_client() as c:
        yield c


def test_run_command_rejects_disallowed_command(client):
    """
    Secure behavior: /run-command must reject commands not in ALLOWED_COMMANDS
    instead of passing them to the OS.
    """
    resp = client.post("/run-command", data={"cmd": "rm -rf /"})
    assert resp.status_code == 400
    assert b"Command not allowed" in resp.data or b"Command" in resp.data


def test_run_command_uses_whitelisted_executable(client):
    """
    Secure behavior: /run-command must use a fixed executable path from
    ALLOWED_COMMANDS and never construct shell commands from raw input.
    """
    with mock.patch.object(mitre_module, "ALLOWED_COMMANDS", {"whoami": ["/usr/bin/whoami"]}), \
         mock.patch("introduction.mitre.subprocess.run") as run_mock:

        run_mock.return_value.stdout = "user\n"
        run_mock.return_value.stderr = ""

        resp = client.post("/run-command", data={"cmd": "whoami"})

    assert resp.status_code == 200
    run_mock.assert_called_once()
    args, kwargs = run_mock.call_args
    assert args[0] == ["/usr/bin/whoami"]
    assert kwargs.get("shell", False) is False


def test_calc_rejects_non_arithmetic_expression(client):
    """
    Secure behavior: /calc must reject expressions containing non-whitelisted
    characters to prevent arbitrary code execution.
    """
    resp = client.post("/calc", data={"expr": "__import__('os').system('id')"})
    assert resp.status_code == 400
    assert b"Unsupported characters" in resp.data or b"Invalid expression" in resp.data


def test_calc_evaluates_simple_arithmetic_expression(client):
    """
    Positive path: simple arithmetic expressions comprised of digits and
    + - * / ( ) should be accepted and evaluated.
    """
    resp = client.post("/calc", data={"expr": "1 + 2 * 3"})
    assert resp.status_code == 200
    assert b"7" in resp.data
