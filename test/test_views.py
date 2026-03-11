import importlib
import types

import pytest


def _import_views_with_minimal_django_stubs(monkeypatch):
    """
    introduction/views.py imports a lot of Django/app modules at import-time.
    This helper stubs only what is needed for importing the module and for calling xxe_parse().
    """
    # --- stub django modules used by views.py ---
    django = types.ModuleType("django")
    contrib = types.ModuleType("django.contrib")
    contrib_messages = types.ModuleType("django.contrib.messages")
    contrib_auth = types.ModuleType("django.contrib.auth")
    contrib_auth_forms = types.ModuleType("django.contrib.auth.forms")
    core = types.ModuleType("django.core")
    core_serializers = types.ModuleType("django.core.serializers")
    http = types.ModuleType("django.http")
    shortcuts = types.ModuleType("django.shortcuts")
    template = types.ModuleType("django.template")
    template_loader = types.ModuleType("django.template.loader")
    views = types.ModuleType("django.views")
    views_decorators = types.ModuleType("django.views.decorators")
    views_decorators_csrf = types.ModuleType("django.views.decorators.csrf")

    # minimal callables referenced by views.py
    contrib_auth.authenticate = lambda *a, **k: None
    contrib_auth.login = lambda *a, **k: None
    contrib_auth_forms.UserCreationForm = object

    http.HttpResponse = object
    http.HttpResponseBadRequest = object
    http.JsonResponse = object

    def _render(request, template_name, context=None):
        return {"template": template_name, "context": context or {}}

    shortcuts.render = _render
    shortcuts.redirect = lambda *a, **k: {"redirect": True}

    template.loader = types.SimpleNamespace()
    template_loader.render_to_string = lambda *a, **k: ""

    views_decorators_csrf.csrf_exempt = lambda f: f

    monkeypatch.setitem(__import__("sys").modules, "django", django)
    monkeypatch.setitem(__import__("sys").modules, "django.contrib", contrib)
    monkeypatch.setitem(__import__("sys").modules, "django.contrib.messages", contrib_messages)
    monkeypatch.setitem(__import__("sys").modules, "django.contrib.auth", contrib_auth)
    monkeypatch.setitem(__import__("sys").modules, "django.contrib.auth.forms", contrib_auth_forms)
    monkeypatch.setitem(__import__("sys").modules, "django.core", core)
    monkeypatch.setitem(__import__("sys").modules, "django.core.serializers", core_serializers)
    monkeypatch.setitem(__import__("sys").modules, "django.http", http)
    monkeypatch.setitem(__import__("sys").modules, "django.shortcuts", shortcuts)
    monkeypatch.setitem(__import__("sys").modules, "django.template", template)
    monkeypatch.setitem(__import__("sys").modules, "django.template.loader", template_loader)
    monkeypatch.setitem(__import__("sys").modules, "django.views", views)
    monkeypatch.setitem(__import__("sys").modules, "django.views.decorators", views_decorators)
    monkeypatch.setitem(__import__("sys").modules, "django.views.decorators.csrf", views_decorators_csrf)

    # --- stub third-party modules imported by views.py but irrelevant to this test ---
    monkeypatch.setitem(__import__("sys").modules, "jwt", types.ModuleType("jwt"))
    monkeypatch.setitem(__import__("sys").modules, "yaml", types.ModuleType("yaml"))
    argon2 = types.ModuleType("argon2")
    argon2.PasswordHasher = object
    monkeypatch.setitem(__import__("sys").modules, "argon2", argon2)
    pil = types.ModuleType("PIL")
    pil_image = types.ModuleType("PIL.Image")
    pil_imagemath = types.ModuleType("PIL.ImageMath")
    monkeypatch.setitem(__import__("sys").modules, "PIL", pil)
    monkeypatch.setitem(__import__("sys").modules, "PIL.Image", pil_image)
    monkeypatch.setitem(__import__("sys").modules, "PIL.ImageMath", pil_imagemath)

    # --- stub requests + requests.structures ---
    requests = types.ModuleType("requests")
    requests.get = lambda *a, **k: None
    requests_structures = types.ModuleType("requests.structures")
    requests_structures.CaseInsensitiveDict = dict
    monkeypatch.setitem(__import__("sys").modules, "requests", requests)
    monkeypatch.setitem(__import__("sys").modules, "requests.structures", requests_structures)

    # --- stub local app imports: introduction.forms/models/utility ---
    intro_forms = types.ModuleType("introduction.forms")
    intro_forms.NewUserForm = object
    monkeypatch.setitem(__import__("sys").modules, "introduction.forms", intro_forms)

    intro_models = types.ModuleType("introduction.models")

    class _CommentsManager:
        def all(self):
            return [types.SimpleNamespace(comment="")]

        def filter(self, **kwargs):
            return types.SimpleNamespace(update=lambda **k: 1)

    intro_models.comments = types.SimpleNamespace(objects=_CommentsManager())

    # other names imported from .models but unused in this test
    for name in [
        "FAANG",
        "AF_admin",
        "AF_session_id",
        "Blogs",
        "CF_user",
        "authLogin",
        "info",
        "login",
        "otp",
        "sql_lab_table",
        "tickits",
    ]:
        setattr(intro_models, name, object)
    monkeypatch.setitem(__import__("sys").modules, "introduction.models", intro_models)

    intro_utility = types.ModuleType("introduction.utility")
    intro_utility.customHash = lambda x: x
    intro_utility.filter_blog = lambda x: x
    monkeypatch.setitem(__import__("sys").modules, "introduction.utility", intro_utility)

    # --- import target module fresh ---
    if "introduction.views" in __import__("sys").modules:
        del __import__("sys").modules["introduction.views"]
    return importlib.import_module("introduction.views")


def test_xxe_parse_disables_external_entities(monkeypatch):
    views = _import_views_with_minimal_django_stubs(monkeypatch)

    # Arrange: capture the feature flag set on the parser
    class ParserSpy:
        def __init__(self):
            self.calls = []

        def setFeature(self, feature, value):
            self.calls.append((feature, value))

    parser_spy = ParserSpy()
    monkeypatch.setattr(views, "make_parser", lambda: parser_spy)

    # parseString is imported into views module namespace; stub it to avoid real XML parsing
    class _DocIter:
        def __iter__(self):
            # Provide one START_ELEMENT event with a <text> node to satisfy the function logic
            node = types.SimpleNamespace(tagName="text", toxml=lambda: "<text>ok</text>")
            yield (views.START_ELEMENT, node)

        def expandNode(self, node):
            return None

    monkeypatch.setattr(views, "parseString", lambda *a, **k: _DocIter())

    # Minimal request stub
    request = types.SimpleNamespace(
        user=types.SimpleNamespace(is_authenticated=True),
        body=b"<root/>",
    )

    # Act
    views.xxe_parse(request)

    # Assert: the security fix requires external entities to be disabled
    assert parser_spy.calls, "Expected parser.setFeature to be called"
    feature, value = parser_spy.calls[0]
    assert feature == views.feature_external_ges
    assert value is False
