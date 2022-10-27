from marshmallow import fields
from nucypher_core.umbral import PublicKey

from porter.fields.base import BaseField
from porter.fields.exceptions import InvalidInputData, InvalidNativeDataTypes


class Key(BaseField, fields.Field):

    def _serialize(self, value, attr, obj, **kwargs):
        return bytes(value).hex()

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            return PublicKey.from_bytes(bytes.fromhex(value))
        except InvalidNativeDataTypes as e:
            raise InvalidInputData(f"Could not convert input for {self.name} to an Umbral Key: {e}")