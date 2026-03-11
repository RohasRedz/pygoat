import importlib
import types

import pytest


def _import_views_with_minimal_django_stubs(monkeypatch):
    """
    introduction/views.py imports a lot of Django/app modules at import-time.
    This helper stubs only what is needed for importing the module and for calling ssrf_lab2().
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


def test_ssrf_lab2_blocks_non_allowlisted_hostname_and_does_not_call_requests(monkeypatch):
    views = _import_views_with_minimal_django_stubs(monkeypatch)

    # Arrange
    get_spy = pytest.MonkeyPatch()
    called = {"count": 0}

    def _requests_get(url):
        called["count"] += 1
        return types.SimpleNamespace(content=b"ok")

    monkeypatch.setattr(views.requests, "get", _requests_get)

    request = types.SimpleNamespace(
        method="POST",
        user=types.SimpleNamespace(is_authenticated=True),
        POST={"url": "http://169.254.169.254/latest/meta-data/"},
    )

    # Act
    resp = views.ssrf_lab2(request)

    # Assert: blocked and no outbound request performed
    assert resp["context"].get("error") == "Invalid URL"
    assert called["count"] == 0


def test_ssrf_lab2_allows_allowlisted_hostname_and_calls_requests_with_safe_url(monkeypatch):
    views = _import_views_with_minimal_django_stubs(monkeypatch)

    # Arrange
    captured = {"url": None}

    def _requests_get(url):
        captured["url"] = url
        return types.SimpleNamespace(content=b"hello")

    monkeypatch.setattr(views.requests, "get", _requests_get)

    request = types.SimpleNamespace(
        method="POST",
        user=types.SimpleNamespace(is_authenticated=True),
        POST={"url": "https://example.com/path?q=1"},
    )

    # Act
    resp = views.ssrf_lab2(request)

    # Assert: allowed and outbound request performed
    assert resp["context"].get("response") == "hello"
    assert captured["url"] == "https://example.com/path?q=1"
