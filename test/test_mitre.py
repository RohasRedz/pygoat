import pytest

# Assumption: module is importable as introduction.mitre in the test environment.
# Note: Validator reported indentation issues in this patch; this test asserts the intended secure behavior
# (reject invalid IP and avoid shell=True) once the module is syntactically valid.
import introduction.mitre as mitre


def test_mitre_lab_17_api_rejects_invalid_ip_and_does_not_invoke_subprocess(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"ip": "127.0.0.1; rm -rf /"}  # command-injection style payload

    popen_spy = mocker.patch.object(mitre.subprocess, "Popen")

    # Act
    resp = mitre.mitre_lab_17_api(request)

    # Assert
    assert getattr(resp, "status_code", None) == 400
    popen_spy.assert_not_called()


def test_command_out_uses_shell_false(mocker):
    # Arrange
    communicate_result = (b"out", b"err")
    proc = mocker.Mock()
    proc.communicate.return_value = communicate_result

    popen_mock = mocker.patch.object(mitre.subprocess, "Popen", return_value=proc)

    # Act
    out, err = mitre.command_out(["nmap", "127.0.0.1"])

    # Assert
    assert (out, err) == communicate_result
    _, kwargs = popen_mock.call_args
    assert kwargs["shell"] is False
