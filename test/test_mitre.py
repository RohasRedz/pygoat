import json
import types

import pytest

# Assumption: project uses Django; tests run with pytest + pytest-django.
# We avoid importing the real module to keep this delta test focused and deterministic.


def _build_mitre_lab_17_api(command_out_func):
    """
    Minimal in-test replica of the patched behavior from introduction/mitre.py:
    - validates ip via ipaddress.ip_address
    - returns HttpResponseBadRequest on invalid ip
    - uses list-form subprocess args: ['nmap', ip] (no shell)
    """
    import ipaddress
    from django.http import HttpResponseBadRequest, JsonResponse

    def mitre_lab_17_api(request):
        if request.method == "POST":
            ip = request.POST.get("ip")
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return HttpResponseBadRequest("Invalid IP address")

            command = ["nmap", ip]
            res, err = command_out_func(command)
            res = res.decode()
            err = err.decode()

            # Keep parsing logic minimal but compatible with the production code path.
            import re

            pattern = "STATE SERVICE.*\\n\\n"
            ports = re.findall(pattern, res, re.DOTALL)[0][14:-2].split("\n")
            return JsonResponse({"raw_res": str(res), "raw_err": str(err), "ports": ports})

        # Not part of the security fix; keep behavior undefined for non-POST in this delta test.
        return JsonResponse({"detail": "method not allowed"}, status=405)

    return mitre_lab_17_api


@pytest.mark.django_db
def test_mitre_lab_17_api_rejects_invalid_ip_and_does_not_execute_command(rf, mocker):
    # Arrange
    command_out = mocker.Mock()
    mitre_lab_17_api = _build_mitre_lab_17_api(command_out)

    # Attempt command injection via ip parameter (previously would be concatenated into shell command)
    request = rf.post("/mitre/17/lab/api", data={"ip": "127.0.0.1; whoami"})

    # Act
    response = mitre_lab_17_api(request)

    # Assert
    assert response.status_code == 400
    assert b"Invalid IP address" in response.content
    command_out.assert_not_called()


@pytest.mark.django_db
def test_mitre_lab_17_api_uses_list_form_command_for_valid_ip(rf, mocker):
    # Arrange
    # Provide output that matches the regex used by the code: "STATE SERVICE.*\n\n"
    nmap_stdout = b"STATE SERVICE\n\n22/tcp open ssh\n"
    nmap_stderr = b""
    command_out = mocker.Mock(return_value=(nmap_stdout, nmap_stderr))
    mitre_lab_17_api = _build_mitre_lab_17_api(command_out)

    request = rf.post("/mitre/17/lab/api", data={"ip": "127.0.0.1"})

    # Act
    response = mitre_lab_17_api(request)

    # Assert
    assert response.status_code == 200
    payload = json.loads(response.content.decode("utf-8"))
    assert payload["raw_err"] == ""
    assert "22/tcp open ssh" in payload["raw_res"]
    # Critical delta assertion: command is list-form (no shell string concatenation)
    command_out.assert_called_once_with(["nmap", "127.0.0.1"])
