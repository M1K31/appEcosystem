import pytest

from ecosystem_client.contracts import UnusableModelOutput, parse_proposals


def test_parses_a_valid_proposal_object():
    text = '{"proposals": [{"action": "containment.block_ip", "action_class": "contain", "target": "10.0.0.5", "parameters": {"ttl_minutes": 30}, "rationale": "repeated failed logins", "confidence": 0.8}]}'
    [p] = parse_proposals(text)
    assert p.action == "containment.block_ip" and p.action_class == "contain" and p.confidence == 0.8


def test_bare_array_is_accepted():
    assert len(parse_proposals('[{"action":"a","action_class":"observe","target":"t","parameters":{},"rationale":"r","confidence":0.1}]')) == 1


def test_unknown_action_class_rejected():
    with pytest.raises(UnusableModelOutput):
        parse_proposals('[{"action":"a","action_class":"delete_everything","target":"t","parameters":{},"rationale":"r","confidence":1}]')


def test_extra_field_rejected():  # e.g. an embedded "approved": true
    with pytest.raises(UnusableModelOutput):
        parse_proposals('[{"action":"a","action_class":"observe","target":"t","parameters":{},"rationale":"r","confidence":1,"approved":true}]')


def test_confidence_out_of_range_rejected():
    with pytest.raises(UnusableModelOutput):
        parse_proposals('[{"action":"a","action_class":"observe","target":"t","parameters":{},"rationale":"r","confidence":1.5}]')


def test_non_json_is_unusable():
    with pytest.raises(UnusableModelOutput):
        parse_proposals("I cannot help with that.")


def test_prose_wrapped_json_is_unusable_when_ambiguous():
    with pytest.raises(UnusableModelOutput):
        parse_proposals('here you go {"proposals": []} and also {"proposals": []}')


def test_unknown_capability_rejected_when_registry_supplied():
    text = '[{"action":"made.up","action_class":"observe","target":"t","parameters":{},"rationale":"r","confidence":1}]'
    with pytest.raises(UnusableModelOutput):
        parse_proposals(text, known_capabilities={"containment.block_ip"})


def test_empty_proposal_list_is_valid():
    assert parse_proposals('{"proposals": []}') == []
