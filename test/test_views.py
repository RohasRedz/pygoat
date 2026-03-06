from types import SimpleNamespace

import pytest


# Assumptions:
# - Module under test is importable as introduction.views.


def _make_request(xml_body: str):
    # xxe_parse reads request.body
    return SimpleNamespace(body=xml_body.encode("utf-8"))


def test_xxe_parse_disables_external_general_entities(mocker):
    from introduction import views

    parser = mocker.Mock()
    mocker.patch("introduction.views.make_parser", return_value=parser)

    # Avoid pulling in XML parsing and DB updates; we only assert the security-relevant flag.
    mocker.patch("introduction.views.parseString", return_value=[])
    mocker.patch("introduction.views.comments.objects.filter")
    mocker.patch("introduction.views.render", return_value="rendered")

    views.xxe_parse(_make_request("<root/>"))

    parser.setFeature.assert_called_once_with(views.feature_external_ges, False)
