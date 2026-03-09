import types

import pytest

# Assumption: repository uses a typical Django app layout where "introduction" is importable.
from introduction import views


def _make_request(*, body=b"<root/>", user_authenticated=True):
    user = types.SimpleNamespace(is_authenticated=user_authenticated)
    req = types.SimpleNamespace(
        user=user,
        body=body,
    )
    return req


def test_xxe_parse_disables_external_general_entities(mocker):
    # Arrange
    request = _make_request(body=b"<root><text>hi</text></root>")

    parser = mocker.Mock()
    make_parser_mock = mocker.patch.object(views, "make_parser", autospec=True, return_value=parser)

    # parseString is imported into views module; patch there.
    # Return an iterable that yields one START_ELEMENT event with a node having tagName 'text'.
    node = mocker.Mock()
    node.tagName = "text"
    node.toxml.return_value = "<text>hi</text>"

    doc_iterable = [(views.START_ELEMENT, node)]
    parse_string_mock = mocker.patch.object(views, "parseString", autospec=True, return_value=doc_iterable)

    # doc.expandNode(node) is called; provide it on the iterable object by using a simple object wrapper.
    class Doc(list):
        def expandNode(self, _node):
            return None

    parse_string_mock.return_value = Doc(doc_iterable)

    render_mock = mocker.patch.object(views, "render", autospec=True, return_value=object())
    comments_mock = mocker.patch.object(views, "comments", autospec=True)
    comments_mock.objects.filter.return_value.update.return_value = 1

    # Act
    result = views.xxe_parse(request)

    # Assert: security fix forces external entities off
    make_parser_mock.assert_called_once()
    parser.setFeature.assert_called_once_with(views.feature_external_ges, False)
    assert result is render_mock.return_value
