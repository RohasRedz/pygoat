import pytest


@pytest.mark.django_db
def test_xxe_parse_disables_external_general_entities(client, django_user_model, monkeypatch):
    # Arrange: login
    django_user_model.objects.create_user(username="u1", password="p1")
    assert client.login(username="u1", password="p1")

    import introduction.views as views

    captured = {"parser": None}

    def fake_parse_string(xml_text, parser=None):
        captured["parser"] = parser
        # Return empty iterator; view only needs to iterate.
        return iter(())

    monkeypatch.setattr(views, "parseString", fake_parse_string)

    # Act
    resp = client.post("/xxe_parse", data=b"<root/>", content_type="text/xml")

    # Assert
    assert resp.status_code == 200
    assert captured["parser"] is not None
    assert captured["parser"].getFeature(views.feature_external_ges) is False
