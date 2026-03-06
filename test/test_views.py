import importlib
import sys
import types


def _install_minimal_django_stubs(monkeypatch):
    def ensure_module(name: str):
        if name in sys.modules:
            return sys.modules[name]
        mod = types.ModuleType(name)
        sys.modules[name] = mod
        return mod

    ensure_module("django")
    ensure_module("django.contrib")
    ensure_module("django.contrib.messages")
    ensure_module("django.contrib.auth")
    ensure_module("django.contrib.auth.forms")
    ensure_module("django.core")
    ensure_module("django.core.serializers")
    ensure_module("django.http")
    ensure_module("django.shortcuts")
    ensure_module("django.template")
    ensure_module("django.template.loader")
    ensure_module("django.views")
    ensure_module("django.views.decorators")
    ensure_module("django.views.decorators.csrf")

    sys.modules["django.contrib.auth"].authenticate = lambda *a, **k: None
    sys.modules["django.contrib.auth"].login = lambda *a, **k: None
    sys.modules["django.contrib.auth.forms"].UserCreationForm = object

    class _HttpResponse:  # pragma: no cover
        def __init__(self, *a, **k):
            self.status_code = 200

        def set_cookie(self, *a, **k):
            return None

        def delete_cookie(self, *a, **k):
            return None

    sys.modules["django.http"].HttpResponse = _HttpResponse
    sys.modules["django.http"].HttpResponseBadRequest = _HttpResponse
    sys.modules["django.http"].JsonResponse = _HttpResponse
    sys.modules["django.shortcuts"].redirect = lambda *a, **k: "redirect"
    sys.modules["django.shortcuts"].render = lambda *a, **k: "rendered"
    sys.modules["django.template"].loader = object
    sys.modules["django.template.loader"].render_to_string = lambda *a, **k: ""
    sys.modules["django.views.decorators.csrf"].csrf_exempt = (lambda f: f)

    ensure_module("PIL")
    ensure_module("PIL.Image")
    ensure_module("PIL.ImageMath")
    sys.modules["PIL.Image"].open = lambda *a, **k: None
    sys.modules["PIL.ImageMath"].eval = lambda *a, **k: None

    ensure_module("requests")
    ensure_module("requests.structures")
    sys.modules["requests.structures"].CaseInsensitiveDict = dict

    ensure_module("argon2")
    sys.modules["argon2"].PasswordHasher = object

    ensure_module("jwt")
    ensure_module("yaml")

    ensure_module("introduction")
    ensure_module("introduction.forms")
    ensure_module("introduction.models")
    ensure_module("introduction.utility")
    sys.modules["introduction.forms"].NewUserForm = object

    models_mod = sys.modules["introduction.models"]
    for name in [
        "FAANG",
        "AF_admin",
        "AF_session_id",
        "Blogs",
        "CF_user",
        "authLogin",
        "comments",
        "info",
        "login",
        "otp",
        "sql_lab_table",
        "tickits",
    ]:
        setattr(models_mod, name, object)

    sys.modules["introduction.utility"].customHash = lambda s: s
    sys.modules["introduction.utility"].filter_blog = lambda s: s

    ensure_module("pygoat")
    ensure_module("pygoat.settings")
    sys.modules["pygoat.settings"].SECRET_COOKIE_KEY = "dummy"


def test_ssrf_lab2_post_ignores_user_supplied_url_and_uses_safe_url(monkeypatch):
    """
    Regression test for security fix:
    ssrf_lab2 must not use a user-supplied URL directly for requests.get().
    The patch hardcodes a safe URL; ensure requests.get is called with that URL
    even if the POSTed url is attacker-controlled.
    """
    _install_minimal_django_stubs(monkeypatch)
    views = importlib.import_module("introduction.views")

    captured = {}

    class DummyResponse:
        content = b"ok"

    def fake_get(url):
        captured["url"] = url
        return DummyResponse()

    monkeypatch.setattr(views.requests, "get", fake_get)

    # Arrange: attacker-controlled URL in POST should be ignored
    req = types.SimpleNamespace(
        method="POST",
        POST={"url": "http://169.254.169.254/latest/meta-data/"},
        user=types.SimpleNamespace(is_authenticated=True),
    )

    # Act
    views.ssrf_lab2(req)

    # Assert
    assert captured["url"] == "http://safe.example.com/api"
    assert captured["url"] != req.POST["url"]
