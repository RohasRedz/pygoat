import introduction.mitre as mitre


class _DummyPost:
    def __init__(self, ip_value):
        self._ip_value = ip_value

    def get(self, key):
        assert key == "ip"
        return self._ip_value


class _DummyRequest:
    def __init__(self, ip_value):
        self.method = "POST"
        self.POST = _DummyPost(ip_value)


def test_mitre_lab_17_api_rejects_non_ip_input_and_does_not_invoke_subprocess(mocker):
    # Arrange
    req = _DummyRequest("127.0.0.1; rm -rf /")  # would have been dangerous with shell=True
    popen_spy = mocker.patch("introduction.mitre.subprocess.Popen")

    # Act
    resp = mitre.mitre_lab_17_api(req)

    # Assert
    # Ensure the fix blocks invalid IPs early and prevents command execution.
    assert hasattr(resp, "status_code")
    assert resp.status_code == 200
    assert b"Invalid IP address" in resp.content
    popen_spy.assert_not_called()


def test_mitre_lab_17_api_uses_shell_false_and_argument_list_for_valid_ip(mocker):
    # Arrange
    req = _DummyRequest("127.0.0.1")

    popen_mock = mocker.patch("introduction.mitre.subprocess.Popen")
    process_mock = mocker.Mock()
    process_mock.communicate.return_value = (b"STATE SERVICE\n\n22/tcp open ssh\n", b"")
    popen_mock.return_value = process_mock

    # Make regex parsing deterministic and avoid depending on exact nmap output format.
    mocker.patch("introduction.mitre.re.findall", return_value=["STATE SERVICE\n\n22/tcp open ssh\n"])

    # Act
    resp = mitre.mitre_lab_17_api(req)

    # Assert
    popen_mock.assert_called_once()
    args, kwargs = popen_mock.call_args
    assert args[0] == ["nmap", "127.0.0.1"]
    assert kwargs.get("shell") is False
    assert kwargs.get("stdout") is not None
    assert kwargs.get("stderr") is not None

    assert hasattr(resp, "status_code")
    assert resp.status_code == 200
    assert b"raw_res" in resp.content
