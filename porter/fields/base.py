import json
from base64 import b64decode, b64encode

import click
from marshmallow import fields

from porter.fields.exceptions import InvalidInputData


class BaseField:

    click_type = click.STRING

    def __init__(self, *args, **kwargs):
        self.click = kwargs.pop('click', None)
        super().__init__(*args, **kwargs)


#
# Very common, simple field types to build on.
#

class String(BaseField, fields.String):
    pass


class List(BaseField, fields.List):
    pass


class StringList(List):
    """
    Expects a delimited string, if input is not already a list. The string is split using the delimiter arg
    (defaults to ',' if not provided) and returns a corresponding List of object.
    """
    def __init__(self, *args, **kwargs):
        self.delimiter = kwargs.pop('delimiter', ',')
        super().__init__(*args, **kwargs)

    def _deserialize(self, value, attr, data, **kwargs):
        if not isinstance(value, list):
            value = value.split(self.delimiter)
        return super()._deserialize(value, attr, data, **kwargs)


class Integer(BaseField, fields.Integer):
    click_type = click.INT


class PositiveInteger(Integer):
    def _validate(self, value):
        if not value > 0:
            raise InvalidInputData(f"{self.name} must be a positive integer.")


class Base64BytesRepresentation(BaseField, fields.Field):
    """Serializes/Deserializes any object's byte representation to/from bae64."""
    def _serialize(self, value, attr, obj, **kwargs):
        try:
            value_bytes = value if isinstance(value, bytes) else bytes(value)
            return b64encode(value_bytes).decode()
        except Exception as e:
            raise InvalidInputData(
                f"Provided object type, {type(value)}, is not serializable: {e}"
            )

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            return b64decode(value)
        except ValueError as e:
            raise InvalidInputData(f"Could not parse {self.name}: {e}")


class JSON(BaseField, fields.Field):
    """Serializes/Deserializes objects to/from JSON strings."""
    def __init__(self, expected_type=None, *args, **kwargs):
        # enforce type-safety (TODO too strict?)
        self.expected_type = expected_type
        super().__init__(*args, **kwargs)

    def _serialize(self, value, attr, obj, **kwargs):
        if self.expected_type and (type(value) != self.expected_type):
            raise InvalidInputData(
                f"Unexpected object type, {type(value)}; expected {self.expected_type}")

        try:
            value_json = json.dumps(value)
            return value_json
        except Exception as e:
            raise InvalidInputData(
                f"Provided object type, {type(value)}, is not JSON serializable: {e}"
            )

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            result = json.loads(value)
        except Exception as e:
            raise InvalidInputData(f"Invalid JSON: {e}")
        else:
            if self.expected_type and (type(result) != self.expected_type):
                raise InvalidInputData(
                    f"Unexpected object type, {type(result)}; expected {self.expected_type}")

            return result


class JSONDict(BaseField, fields.Dict):
    """Serializes/Deserializes Dictionaries to/from JSON strings."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _serialize(self, value, attr, obj, **kwargs):
        try:
            value = super()._serialize(value, attr, obj, **kwargs)
        except Exception as e:
            raise InvalidInputData(
                f"Could not convert input for {self.name} to JSON: {e}"
            )
        try:
            value_json = json.dumps(value)
            return value_json
        except Exception as e:
            raise InvalidInputData(
                f"Could not convert input for {self.name} to JSON: {e}"
            )

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            result = json.loads(value)
        except Exception as e:
            raise InvalidInputData(
                f"Could not convert input for {self.name} to dictionary: {e}"
            )

        try:
            return super()._deserialize(result, attr, data, **kwargs)
        except Exception as e:
            raise InvalidInputData(
                f"Could not convert input for {self.name} to dictionary: {e}"
            )
