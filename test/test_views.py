import introduction.views as views


def test_xxe_parse_disables_external_general_entities(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.body = b"<root><text>hello</text></root>"

    parser = mocker.Mock()
    make_parser_spy = mocker.patch.object(views, "make_parser", return_value=parser)

    parse_string_spy = mocker.patch.object(
        views,
        "parseString",
        return_value=[(views.START_ELEMENT, mocker.Mock(tagName="text", toxml=lambda: "<text>hello</text>"))],
    )

    mocker.patch.object(views.comments.objects, "filter", return_value=mocker.Mock(update=mocker.Mock()))

    # Act
    views.xxe_parse(request)

    # Assert
    make_parser_spy.assert_called_once()
    parser.setFeature.assert_called_once_with(views.feature_external_ges, False)
    parse_string_spy.assert_called_once()
