import pytest

# Assumption: Django app module path is "introduction.views" as per source file path.
import introduction.views as views


class _DummyUser:
    def __init__(self, authenticated=True):
        self.is_authenticated = authenticated


class _DummyRequest:
    def __init__(self, body: bytes, user_authenticated=True):
        self.method = "POST"
        self.body = body
        self.user = _DummyUser(user_authenticated)


def test_xxe_parse_disables_external_general_entities(mocker):
    # Arrange
    req = _DummyRequest(body=b"<root><text>Hello</text></root>")

    parser = mocker.Mock()
    make_parser_mock = mocker.patch.object(views, "make_parser", autospec=True, return_value=parser)

    # parseString is used with parser=parser; stub it to return an iterable with START_ELEMENT event
    class _Doc:
        def __iter__(self):
            return iter([(views.START_ELEMENT, types.SimpleNamespace(tagName="text", toxml=lambda: "<text>Hello</text>"))])

        def expandNode(self, node):
            return None

    import types

    parse_string_mock = mocker.patch.object(views, "parseString", autospec=True, return_value=_Doc())

    # comments.objects.filter(id=1).update(comment=text)
    comments_filter = mocker.Mock()
    comments_filter.update.return_value = 1
    mocker.patch.object(views.comments.objects, "filter", autospec=True, return_value=comments_filter)

    render_mock = mocker.patch.object(views, "render", autospec=True)

    # Act
    views.xxe_parse(req)

    # Assert
    parser.setFeature.assert_called_once_with(views.feature_external_ges, False)
    render_mock.assert_called_once()
