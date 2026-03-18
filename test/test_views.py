import types

import pytest


# Assumptions:
# - Django is installed and importable in the test environment.
# - The project module path is "introduction.views".


def _make_request(*, authenticated=True, body=b"<root><text>hi</text></root>"):
    user = types.SimpleNamespace(is_authenticated=authenticated)
    return types.SimpleNamespace(user=user, body=body)


def test_xxe_parse_disables_external_general_entities(mocker):
    from introduction import views

    request = _make_request()

    parser_mock = mocker.Mock()
    make_parser_mock = mocker.patch.object(views, "make_parser", autospec=True, return_value=parser_mock)

    # Avoid real XML parsing; just ensure parseString is called with our parser
    pulldom_doc = [(views.START_ELEMENT, types.SimpleNamespace(tagName="text", toxml=lambda: "<text>hi</text>"))]
    parse_string_mock = mocker.patch.object(views, "parseString", autospec=True, return_value=pulldom_doc)

    # comments.objects.filter(...).update(...) should be callable
    comments_model = mocker.Mock()
    comments_model.objects.filter.return_value.update.return_value = 1
    mocker.patch.object(views, "comments", comments_model)

    mocker.patch.object(views, "render", autospec=True)

    views.xxe_parse(request)

    make_parser_mock.assert_called_once()
    parser_mock.setFeature.assert_called_with(views.feature_external_ges, False)
    parse_string_mock.assert_called_once()
