import pytest

from introduction import views


def test_xxe_parse_disables_external_general_entities(mocker):
    parser_instance = mocker.Mock()
    make_parser_mock = mocker.patch("introduction.views.make_parser", return_value=parser_instance)

    doc_iter = [(views.START_ELEMENT, mocker.Mock(tagName="text", toxml=lambda: "<text>hi</text>"))]
    parse_string_mock = mocker.patch("introduction.views.parseString", return_value=doc_iter)

    request = mocker.Mock()
    request.user.is_authenticated = True
    request.body = b"<text>hi</text>"

    mocker.patch("introduction.views.comments.objects.filter", return_value=mocker.Mock(update=mocker.Mock()))

    views.xxe_parse(request)

    make_parser_mock.assert_called_once()
    parser_instance.setFeature.assert_called_once_with(views.feature_external_ges, False)
    parse_string_mock.assert_called_once()
