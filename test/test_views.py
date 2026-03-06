import types

import pytest

# Assumption: tests run with repo root on PYTHONPATH so `introduction` is importable.
import introduction.views as views


def test_xxe_parse_disables_external_general_entities(mocker):
    # Arrange
    parser = mocker.Mock()
    make_parser_mock = mocker.patch.object(views, "make_parser", autospec=True, return_value=parser)

    # Provide a minimal pulldom-like iterable and node to satisfy the function's loop.
    node = mocker.Mock()
    node.tagName = "text"
    node.toxml.return_value = "<text>hello</text>"

    doc_iterable = [(views.START_ELEMENT, node)]
    parse_string_mock = mocker.patch.object(views, "parseString", autospec=True, return_value=doc_iterable)

    # expandNode is called on `doc` (the iterable returned by parseString)
    doc_iterable.expandNode = mocker.Mock()

    # Avoid DB access and template rendering
    mocker.patch.object(views, "comments", autospec=True)
    views.comments.objects.filter.return_value.update.return_value = 1
    mocker.patch.object(views, "render", autospec=True, return_value="rendered")

    request = types.SimpleNamespace(
        user=types.SimpleNamespace(is_authenticated=True),
        body=b"<text>hello</text>",
    )

    # Act
    result = views.xxe_parse(request)

    # Assert
    make_parser_mock.assert_called_once()
    parser.setFeature.assert_called_once_with(views.feature_external_ges, False)
    parse_string_mock.assert_called_once()
    assert result == "rendered"
