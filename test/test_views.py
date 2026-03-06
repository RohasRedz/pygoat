import introduction.views as views


def test_xxe_parse_disables_external_general_entities(mocker):
    # Arrange
    parser = mocker.Mock()
    make_parser = mocker.patch("introduction.views.make_parser", return_value=parser)

    # Avoid real XML parsing; we only care that parser is configured securely.
    mocker.patch("introduction.views.parseString", return_value=[])

    request = mocker.Mock()
    request.user.is_authenticated = True
    request.body = b"<root><text>hello</text></root>"

    # Act
    views.xxe_parse(request)

    # Assert
    make_parser.assert_called_once()
    parser.setFeature.assert_any_call(views.feature_external_ges, False)
