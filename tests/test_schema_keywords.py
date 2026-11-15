"""The contract validator applies the JSON-Schema keywords capability inputs_schemas use."""
import pytest

from ecosystem_client.contracts import validate_against_schema as v


@pytest.mark.parametrize("schema,value,ok", [
    ({"type": "integer", "maximum": 10}, 10, True),
    ({"type": "integer", "maximum": 10}, 11, False),
    ({"type": "integer", "exclusiveMaximum": 10}, 10, False),
    ({"type": "integer", "exclusiveMinimum": 1}, 1, False),
    ({"type": "string", "maxLength": 3}, "abcd", False),
    ({"type": "string", "maxLength": 3}, "abc", True),
    ({"type": "array", "maxItems": 2}, [1, 2, 3], False),
    ({"anyOf": [{"type": "string"}, {"type": "integer"}]}, 3, True),
    ({"anyOf": [{"type": "string"}, {"type": "integer"}]}, [3], False),
    ({"allOf": [{"type": "integer"}, {"minimum": 5}]}, 4, False),
    ({"not": {"type": "string"}}, "x", False),
    ({"not": {"type": "string"}}, 1, True),
])
def test_keyword(schema, value, ok):
    assert (v(value, schema) == []) is ok


EXACTLY_ONE = {
    "type": "object",
    "properties": {"threat_id": {"type": "integer", "minimum": 1}, "text": {"type": "string", "maxLength": 8000}},
    "additionalProperties": False,
    "oneOf": [{"required": ["threat_id"]}, {"required": ["text"]}],
}


@pytest.mark.parametrize("params,ok", [
    ({"threat_id": 3}, True), ({"text": "x"}, True),
    ({"threat_id": 3, "text": "x"}, False), ({}, False), ({"other": 1}, False),
])
def test_one_of_means_exactly_one(params, ok):
    assert (v(params, EXACTLY_ONE) == []) is ok


def test_no_properties_and_additional_false_means_no_keys():
    schema = {"type": "object", "properties": {}, "additionalProperties": False}
    assert v({}, schema) == []
    assert v({"anything": 1}, schema)
