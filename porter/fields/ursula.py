from eth_utils import to_checksum_address
from marshmallow import fields

from porter.cli.types import EIP55_CHECKSUM_ADDRESS
from porter.fields.base import String
from porter.fields.exceptions import InvalidInputData
from porter.fields.key import Key
from porter.schema import BaseSchema


class UrsulaChecksumAddress(String):
    """Ursula checksum address."""
    click_type = EIP55_CHECKSUM_ADDRESS

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            return to_checksum_address(value=value)
        except ValueError as e:
            raise InvalidInputData(f"Could not convert input for {self.name} to a valid checksum address: {e}")


class UrsulaInfoSchema(BaseSchema):
    """Schema for the result of sampling of Ursulas."""
    checksum_address = UrsulaChecksumAddress()
    uri = fields.URL()
    encrypting_key = Key()

    # maintain field declaration ordering
    class Meta:
        ordered = True
