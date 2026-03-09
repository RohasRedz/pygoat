# Assumption: project uses pytest and imports modules by package name "introduction".
# If the repo uses a different import root, adjust PYTHONPATH accordingly when running tests.

import pytest

import introduction.mitre as mitre


def test_mitre_lab_17_api_rejects_non_ipv4_input_and_does_not_execute_subprocess(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST.get.return_value = "1.2.3.4; rm -rf /"  # attacker-controlled input

    popen_spy = mocker.patch("introduction.mitre.subprocess.Popen")

    # Act / Assert
    with pytest.raises(ValueError, match="Invalid IP"):
        mitre.mitre_lab_17_api(request)

    popen_spy.assert_not_called()


def test_mitre_lab_17_api_uses_shell_false_and_argv_list(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST.get.return_value = "127.0.0.1"

    # Ensure regex check passes deterministically
    mocker.patch("introduction.mitre.re.match", return_value=True)

    # Avoid depending on nmap output parsing; just make it return something that matches the regex used.
    mocker.patch(
        "introduction.mitre.command_out",
        return_value=(b"STATE SERVICE\n\n80/tcp open http\n", b""),
    )

    json_response = mocker.patch("introduction.mitre.JsonResponse", side_effect=lambda payload: payload)

    # Act
    result = mitre.mitre_lab_17_api(request)

    # Assert
    assert "ports" in result
    json_response.assert_called_once()
    # command_out should be called with argv list, not a string
    mitre.command_out.assert_called_once_with(["nmap", "127.0.0.1"])
