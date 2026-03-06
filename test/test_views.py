import pytest


# Assumptions:
# - Module path is "introduction.views" as implied by file_path.
from introduction import views


def _make_request(body: bytes, authenticated: bool = True):
    class _User:
        is_authenticated = authenticated

    class _Req:
        def __init__(self):
            self.user = _User()
            self.body = body

    return _Req()


def test_xxe_parse_disables_external_general_entities(mocker):
    # Arrange
    req = _make_request(b"<root><text>Hello</text></root>")

    parser_mock = mocker.Mock()
    make_parser_mock = mocker.patch.object(views, "make_parser", return_value=parser_mock)

    # parseString returns an iterable of (event, node). Provide a minimal START_ELEMENT event.
    class _Node:
        tagName = "text"

        def toxml(self):
            return "<text>Hello</text>"

    doc_iter = [(views.START_ELEMENT, _Node())]
    mocker.patch.object(views, "parseString", return_value=doc_iter)

    # doc.expandNode is called on the returned doc object; easiest is to make doc_iter have expandNode.
    # We'll wrap it in an object that is iterable and has expandNode.
    class _Doc(list):
        def expandNode(self, node):
            return None

    mocker.patch.object(views, "parseString", return_value=_Doc(doc_iter))

    comments_filter_mock = mocker.Mock()
    comments_filter_mock.update.return_value = 1
    mocker.patch.object(views.comments.objects, "filter", return_value=comments_filter_mock)

    mocker.patch.object(views, "render", lambda request, template: (template, request))

    # Act
    views.xxe_parse(req)

    # Assert
    make_parser_mock.assert_called_once()
    parser_mock.setFeature.assert_called_once_with(views.feature_external_ges, False)
