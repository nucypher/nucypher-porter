from eth_utils import to_checksum_address

from porter.cli.types import EIP55_CHECKSUM_ADDRESS
from porter.fields.base import String
from porter.fields.exceptions import InvalidInputData


class UrsulaChecksumAddress(String):
    """Ursula checksum address."""
    click_type = EIP55_CHECKSUM_ADDRESS

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            return to_checksum_address(value=value)
        except ValueError as e:
            raise InvalidInputData(f"Could not convert input for {self.name} to a valid checksum address: {e}")
