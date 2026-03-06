import introduction.mitre as mitre


def test_mitre_lab_17_api_rejects_invalid_ip_returns_400(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"ip": "127.0.0.1; whoami"}  # previously could lead to command injection

    # Act
    resp = mitre.mitre_lab_17_api(request)

    # Assert
    assert resp.status_code == 400
    assert b"Invalid IP address" in resp.content


def test_mitre_lab_17_api_uses_safe_subprocess_invocation_no_shell(mocker):
    # Arrange
    request = mocker.Mock()
    request.method = "POST"
    request.POST = {"ip": "127.0.0.1"}

    popen = mocker.patch("introduction.mitre.subprocess.Popen")
    proc = mocker.Mock()
    proc.communicate.return_value = (b"STATE SERVICE\n\n22/tcp open ssh\n", b"")
    popen.return_value = proc

    # Act
    resp = mitre.mitre_lab_17_api(request)

    # Assert
    assert resp.status_code == 200
    popen.assert_called_once()
    args, kwargs = popen.call_args
    assert args[0] == ["nmap", "127.0.0.1"]
    assert kwargs.get("shell") is False
