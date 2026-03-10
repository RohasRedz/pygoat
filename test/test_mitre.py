import pytest

# Assumption: tests run with repo root on PYTHONPATH so `introduction` is importable.
import introduction.mitre as mitre


def test_mitre_lab_17_api_rejects_non_ip_input_and_does_not_execute_subprocess(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST.get.return_value = "127.0.0.1; rm -rf /"  # injection attempt should be rejected

    popen_spy = mocker.patch.object(mitre.subprocess, "Popen")

    # Act
    response = mitre.mitre_lab_17_api(request)

    # Assert
    assert isinstance(response, mitre.HttpResponseBadRequest)
    assert response.status_code == 400
    popen_spy.assert_not_called()


def test_mitre_lab_17_api_uses_subprocess_without_shell_and_with_argument_list(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST.get.return_value = "127.0.0.1"

    process = mocker.Mock()
    process.communicate.return_value = (
        b"STATE SERVICE\n\n22/tcp open ssh\n",
        b"",
    )
    popen_spy = mocker.patch.object(mitre.subprocess, "Popen", return_value=process)

    # Act
    response = mitre.mitre_lab_17_api(request)

    # Assert
    assert isinstance(response, mitre.JsonResponse)
    popen_spy.assert_called_once()
    args, kwargs = popen_spy.call_args
    assert args[0] == ["nmap", "127.0.0.1"]
    assert "shell" not in kwargs  # previously shell=True; now must not be set
    assert kwargs["stdout"] == mitre.subprocess.PIPE
    assert kwargs["stderr"] == mitre.subprocess.PIPE
