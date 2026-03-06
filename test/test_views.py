import importlib
import sys
import types


def _install_minimal_django_stubs(monkeypatch):
    """
    introduction.views imports many Django/PIL/etc modules at import time.
    Provide minimal stubs so we can import the module and call xxe_parse
    without requiring Django to be installed for this unit test.
    """
    def ensure_module(name: str):
        if name in sys.modules:
            return sys.modules[name]
        mod = types.ModuleType(name)
        sys.modules[name] = mod
        return mod

    # django stubs
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

    # PIL stubs
    ensure_module("PIL")
    ensure_module("PIL.Image")
    ensure_module("PIL.ImageMath")
    sys.modules["PIL.Image"].open = lambda *a, **k: None
    sys.modules["PIL.ImageMath"].eval = lambda *a, **k: None

    # requests.structures stub
    ensure_module("requests")
    ensure_module("requests.structures")
    sys.modules["requests.structures"].CaseInsensitiveDict = dict

    # argon2 stub
    ensure_module("argon2")
    sys.modules["argon2"].PasswordHasher = object

    # jwt/yaml stubs
    ensure_module("jwt")
    ensure_module("yaml")

    # local imports used by introduction.views: .forms, .models, .utility
    ensure_module("introduction")
    ensure_module("introduction.forms")
    ensure_module("introduction.models")
    ensure_module("introduction.utility")

    sys.modules["introduction.forms"].NewUserForm = object

    # Provide dummy model attributes referenced at import time
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

    # pygoat.settings import used later in file
    ensure_module("pygoat")
    ensure_module("pygoat.settings")
    sys.modules["pygoat.settings"].SECRET_COOKIE_KEY = "dummy"


def test_xxe_parse_disables_external_general_entities(monkeypatch):
    """
    Regression test for security fix:
    xxe_parse must disable external general entities (feature_external_ges=False)
    to mitigate XXE.
    """
    _install_minimal_django_stubs(monkeypatch)

    # Import after stubbing dependencies
    views = importlib.import_module("introduction.views")

    # Arrange: stub parser and parseString to avoid real XML parsing
    class DummyParser:
        def __init__(self):
            self.features = []

        def setFeature(self, feature, value):
            self.features.append((feature, value))

    dummy_parser = DummyParser()
    monkeypatch.setattr(views, "make_parser", lambda: dummy_parser)

    def fake_parse_string(_xml, parser):
        # Ensure the parser passed is our dummy parser
        assert parser is dummy_parser
        # Return an iterable that won't execute the vulnerable path further
        return []

    monkeypatch.setattr(views, "parseString", fake_parse_string)

    # Also stub comments.objects.filter(...).update(...) used near end of function
    class DummyComments:
        class objects:
            @staticmethod
            def filter(**kwargs):
                class _Q:
                    @staticmethod
                    def update(**kwargs2):
                        return 1
                return _Q()

    monkeypatch.setattr(views, "comments", DummyComments)

    # Provide a minimal request with body
    req = types.SimpleNamespace(body=b"<root/>", user=types.SimpleNamespace(is_authenticated=True))

    # Act
    views.xxe_parse(req)

    # Assert: feature_external_ges must be disabled
    assert (views.feature_external_ges, False) in dummy_parser.features
    assert (views.feature_external_ges, True) not in dummy_parser.features
