import types

import pytest

# Assumption: tests run with repo root on PYTHONPATH so `introduction` is importable.
import introduction.views as views


def test_xxe_parse_disables_external_general_entities(mocker):
    # Arrange
    parser = mocker.Mock()
    make_parser = mocker.patch.object(views, "make_parser", return_value=parser)

    # parseString is imported into module namespace; mock it to avoid real XML parsing
    doc_iter = [(views.START_ELEMENT, types.SimpleNamespace(tagName="text", toxml=lambda: "<text>ok</text>"))]
    parse_string = mocker.patch.object(views, "parseString", return_value=doc_iter)

    # comments.objects.filter(...).update(...) is called; mock the ORM chain
    comments = mocker.patch.object(views, "comments")
    comments.objects.all.return_value = [types.SimpleNamespace(comment="seed")]
    comments.objects.filter.return_value.update.return_value = 1

    request = types.SimpleNamespace(
        user=types.SimpleNamespace(is_authenticated=True),
        body=b"<text>ok</text>",
    )

    # Act
    views.xxe_parse(request)

    # Assert: regression for XXE fix - external general entities must be disabled
    make_parser.assert_called_once()
    parser.setFeature.assert_called_once_with(views.feature_external_ges, False)
    parse_string.assert_called_once()
