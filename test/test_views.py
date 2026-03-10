import importlib
import types

import pytest


def _import_views_with_minimal_django_stubs(monkeypatch):
    """
    introduction/views.py imports Django and other libs at import-time.
    Stub only what is needed for the changed XXE code path to be importable.
    """
    # --- django stubs ---
    django = types.ModuleType("django")
    django_contrib = types.ModuleType("django.contrib")
    django_contrib_messages = types.ModuleType("django.contrib.messages")
    django_contrib_auth = types.ModuleType("django.contrib.auth")
    django_contrib_auth_forms = types.ModuleType("django.contrib.auth.forms")
    django_core = types.ModuleType("django.core")
    django_core_serializers = types.ModuleType("django.core.serializers")
    django_http = types.ModuleType("django.http")
    django_shortcuts = types.ModuleType("django.shortcuts")
    django_template = types.ModuleType("django.template")
    django_template_loader = types.ModuleType("django.template.loader")
    django_views = types.ModuleType("django.views")
    django_views_decorators = types.ModuleType("django.views.decorators")
    django_views_decorators_csrf = types.ModuleType("django.views.decorators.csrf")

    # Minimal callables used throughout module (not executed in our tests)
    django_contrib_auth.authenticate = lambda *a, **k: None
    django_contrib_auth.login = lambda *a, **k: None
    django_contrib_auth_forms.UserCreationForm = object

    class _HttpResponse:  # pragma: no cover
        def __init__(self, *a, **k):
            self.content = b""
            self.status_code = 200

        def set_cookie(self, *a, **k):
            return None

        def delete_cookie(self, *a, **k):
            return None

        def __setitem__(self, k, v):
            return None

    django_http.HttpResponse = _HttpResponse
    django_http.HttpResponseBadRequest = _HttpResponse
    django_http.JsonResponse = _HttpResponse

    django_shortcuts.redirect = lambda *a, **k: None
    django_shortcuts.render = lambda *a, **k: None

    django_template.loader = django_template_loader
    django_template_loader.render_to_string = lambda *a, **k: ""

    def _csrf_exempt(func):
        return func

    django_views_decorators_csrf.csrf_exempt = _csrf_exempt

    monkeypatch.setitem(__import__("sys").modules, "django", django)
    monkeypatch.setitem(__import__("sys").modules, "django.contrib", django_contrib)
    monkeypatch.setitem(__import__("sys").modules, "django.contrib.messages", django_contrib_messages)
    monkeypatch.setitem(__import__("sys").modules, "django.contrib.auth", django_contrib_auth)
    monkeypatch.setitem(__import__("sys").modules, "django.contrib.auth.forms", django_contrib_auth_forms)
    monkeypatch.setitem(__import__("sys").modules, "django.core", django_core)
    monkeypatch.setitem(__import__("sys").modules, "django.core.serializers", django_core_serializers)
    monkeypatch.setitem(__import__("sys").modules, "django.http", django_http)
    monkeypatch.setitem(__import__("sys").modules, "django.shortcuts", django_shortcuts)
    monkeypatch.setitem(__import__("sys").modules, "django.template", django_template)
    monkeypatch.setitem(__import__("sys").modules, "django.template.loader", django_template_loader)
    monkeypatch.setitem(__import__("sys").modules, "django.views", django_views)
    monkeypatch.setitem(__import__("sys").modules, "django.views.decorators", django_views_decorators)
    monkeypatch.setitem(__import__("sys").modules, "django.views.decorators.csrf", django_views_decorators_csrf)

    # --- third-party stubs imported at module import-time ---
    jwt = types.ModuleType("jwt")
    jwt.decode = lambda *a, **k: {}
    jwt.encode = lambda *a, **k: "token"
    monkeypatch.setitem(__import__("sys").modules, "jwt", jwt)

    yaml = types.ModuleType("yaml")
    yaml.load = lambda *a, **k: {}
    yaml.Loader = object
    monkeypatch.setitem(__import__("sys").modules, "yaml", yaml)

    argon2 = types.ModuleType("argon2")
    class _PasswordHasher:  # pragma: no cover
        def verify(self, *a, **k):
            return True
    argon2.PasswordHasher = _PasswordHasher
    monkeypatch.setitem(__import__("sys").modules, "argon2", argon2)

    PIL = types.ModuleType("PIL")
    PIL_Image = types.ModuleType("PIL.Image")
    PIL_ImageMath = types.ModuleType("PIL.ImageMath")
    monkeypatch.setitem(__import__("sys").modules, "PIL", PIL)
    monkeypatch.setitem(__import__("sys").modules, "PIL.Image", PIL_Image)
    monkeypatch.setitem(__import__("sys").modules, "PIL.ImageMath", PIL_ImageMath)

    requests_structures = types.ModuleType("requests.structures")
    requests_structures.CaseInsensitiveDict = dict
    monkeypatch.setitem(__import__("sys").modules, "requests.structures", requests_structures)

    # --- local package stubs (relative imports) ---
    intro_forms = types.ModuleType("introduction.forms")
    intro_forms.NewUserForm = object
    monkeypatch.setitem(__import__("sys").modules, "introduction.forms", intro_forms)

    intro_models = types.ModuleType("introduction.models")
    # Provide attributes referenced at import-time; not used in our tests.
    for name in [
        "FAANG", "AF_admin", "AF_session_id", "Blogs", "CF_user", "authLogin",
        "comments", "info", "login", "otp", "sql_lab_table", "tickits"
    ]:
        setattr(intro_models, name, object)
    monkeypatch.setitem(__import__("sys").modules, "introduction.models", intro_models)

    intro_utility = types.ModuleType("introduction.utility")
    intro_utility.customHash = lambda x: x
    intro_utility.filter_blog = lambda x: x
    monkeypatch.setitem(__import__("sys").modules, "introduction.utility", intro_utility)

    pygoat_settings = types.ModuleType("pygoat.settings")
    pygoat_settings.SECRET_COOKIE_KEY = "secret"
    monkeypatch.setitem(__import__("sys").modules, "pygoat.settings", pygoat_settings)

    # Import (or reload) the module under test
    return importlib.import_module("introduction.views")


def test_xxe_parse_disables_external_general_entities(monkeypatch):
    """
    Regression test for XXE fix:
    ensure parser.setFeature(feature_external_ges, False) is used (was True).
    """
    views = _import_views_with_minimal_django_stubs(monkeypatch)

    # Arrange: stub make_parser() to return a parser spy
    class ParserSpy:
        def __init__(self):
            self.calls = []

        def setFeature(self, feature, value):
            self.calls.append((feature, value))

    parser_spy = ParserSpy()
    monkeypatch.setattr(views, "make_parser", lambda: parser_spy)

    # Also stub parseString to avoid real XML parsing; return iterable expected by code.
    monkeypatch.setattr(views, "parseString", lambda *a, **k: [(views.START_ELEMENT, types.SimpleNamespace(tagName="text", toxml=lambda: "<text>x</text>"))])

    # Stub comments.objects.filter(...).update(...) chain used by xxe_parse
    class _CommentsObjects:
        def filter(self, **kwargs):
            return self

        def update(self, **kwargs):
            return 1

    views.comments = types.SimpleNamespace(objects=_CommentsObjects())

    # Stub render to avoid Django template rendering
    monkeypatch.setattr(views, "render", lambda *a, **k: "ok")

    # Act
    req = types.SimpleNamespace(body=b"<root/>")
    views.xxe_parse(req)

    # Assert: the security fix forces external general entities off
    assert (views.feature_external_ges, False) in parser_spy.calls
    assert (views.feature_external_ges, True) not in parser_spy.calls
