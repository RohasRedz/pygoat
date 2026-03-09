import pytest

# Assumption: repository uses "introduction" as a top-level Python package.
from introduction import views


def test_xxe_parse_disables_external_general_entities(mocker):
    # Arrange
    request = mocker.Mock()
    request.user.is_authenticated = True
    request.body = b"<root><text>hello</text></root>"

    parser = mocker.Mock()
    make_parser = mocker.patch("introduction.views.make_parser", autospec=True, return_value=parser)

    # Avoid real XML parsing; provide a minimal iterable that matches the loop usage
    fake_doc = [(views.START_ELEMENT, mocker.Mock(tagName="text", toxml=lambda: "<text>hello</text>"))]
    parse_string = mocker.patch("introduction.views.parseString", autospec=True, return_value=fake_doc)

    # Avoid DB update side effects
    comments_filter = mocker.Mock()
    comments_filter.update.return_value = 1
    mocker.patch("introduction.views.comments.objects.filter", autospec=True, return_value=comments_filter)

    mocker.patch("introduction.views.render", autospec=True)

    # Act
    views.xxe_parse(request)

    # Assert: secure behavior after fix - external entities disabled
    make_parser.assert_called_once()
    parser.setFeature.assert_called_once_with(views.feature_external_ges, False)
    parse_string.assert_called_once()
