import click
from eth_utils import to_checksum_address


class ChecksumAddress(click.ParamType):
    name = 'checksum_address'

    def convert(self, value, param, ctx):
        try:
            value = to_checksum_address(value=value)
        except ValueError:
            self.fail("Invalid ethereum address")
        else:
            return value


EIP55_CHECKSUM_ADDRESS = ChecksumAddress()
