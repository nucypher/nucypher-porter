import click
from marshmallow import INCLUDE, Schema, validates_schema
from marshmallow import fields as marshmallow_fields

from porter.cli.types import EIP55_CHECKSUM_ADDRESS
from porter.fields.base import JSON, PositiveInteger, StringList
from porter.fields.exceptions import InvalidArgumentCombo, InvalidInputData
from porter.fields.retrieve import CapsuleFrag, RetrievalKit
from porter.fields.taco import (
    EncryptedThresholdDecryptionRequestField,
    EncryptedThresholdDecryptionResponseField,
)
from porter.fields.treasuremap import TreasureMap
from porter.fields.umbralkey import UmbralKey
from porter.fields.ursula import UrsulaChecksumAddress


class BaseSchema(Schema):

    class Meta:
        unknown = INCLUDE   # pass through any data that isn't defined as a field

    def handle_error(self, error, data, many, **kwargs):
        raise InvalidInputData(error)


def option_ursula():
    return click.option(
        '--ursula',
        '-u',
        help="Ursula checksum address",
        type=EIP55_CHECKSUM_ADDRESS,
        required=True)


def option_bob_encrypting_key():
    return click.option(
        '--bob-encrypting-key',
        '-bek',
        help="Bob's encrypting key as a hexadecimal string",
        type=click.STRING,
        required=True)


class UrsulaInfoSchema(BaseSchema):
    """Schema for the result of sampling of Ursulas."""
    checksum_address = UrsulaChecksumAddress()
    uri = marshmallow_fields.URL()
    encrypting_key = UmbralKey()

    # maintain field declaration ordering
    class Meta:
        ordered = True


#
# Common Endpoints
#


class GetUrsulas(BaseSchema):
    quantity = PositiveInteger(
        required=True,
        load_only=True,
        click=click.option(
            '--quantity',
            '-n',
            help="Total number of Ursulas needed",
            type=click.INT, required=True))

    # optional
    exclude_ursulas = StringList(
        UrsulaChecksumAddress(),
        click=click.option(
            '--exclude-ursula',
            '-e',
            help="Ursula checksum address to exclude from sample",
            multiple=True,
            type=EIP55_CHECKSUM_ADDRESS,
            required=False,
            default=[]),
        required=False,
        load_only=True)

    include_ursulas = StringList(
        UrsulaChecksumAddress(),
        click=click.option(
            '--include-ursula',
            '-i',
            help="Ursula checksum address to include in sample",
            multiple=True,
            type=EIP55_CHECKSUM_ADDRESS,
            required=False,
            default=[]),
        required=False,
        load_only=True)

    timeout = PositiveInteger(
        required=False,
        load_only=True,
        click=click.option(
            "--timeout",
            "-t",
            help="Timeout for getting the required quantity of ursulas",
            type=click.INT,
            required=False,
        ),
    )

    # output
    ursulas = marshmallow_fields.List(marshmallow_fields.Nested(UrsulaInfoSchema), dump_only=True)

    @validates_schema
    def check_valid_quantity_and_include_ursulas(self, data, **kwargs):
        # TODO does this make sense - perhaps having extra ursulas could be a good thing if some are down or can't
        #  be contacted at that time
        ursulas_to_include = data.get("include_ursulas")
        if ursulas_to_include and len(ursulas_to_include) > data["quantity"]:
            raise InvalidArgumentCombo(
                "Ursulas to include is greater than quantity requested"
            )

    @validates_schema
    def check_include_and_exclude_are_mutually_exclusive(self, data, **kwargs):
        ursulas_to_include = data.get('include_ursulas') or []
        ursulas_to_exclude = data.get('exclude_ursulas') or []
        common_ursulas = set(ursulas_to_include).intersection(ursulas_to_exclude)
        if len(common_ursulas) > 0:
            raise InvalidArgumentCombo(f"Ursulas to include and exclude are not mutually exclusive; "
                                       f"common entries {common_ursulas}")


#
# PRE Endpoints
#

class PRERevoke(BaseSchema):
    pass  # TODO need to understand revoke process better


class PRERetrievalOutcomeSchema(BaseSchema):
    """Schema for the result of /retrieve_cfrags endpoint."""

    cfrags = marshmallow_fields.Dict(keys=UrsulaChecksumAddress(), values=CapsuleFrag())
    errors = marshmallow_fields.Dict(
        keys=UrsulaChecksumAddress(), values=marshmallow_fields.String()
    )

    # maintain field declaration ordering
    class Meta:
        ordered = True


class PRERetrieveCFrags(BaseSchema):
    treasure_map = TreasureMap(
        required=True,
        load_only=True,
        click=click.option(
            '--treasure-map',
            '-t',
            help="Unencrypted Treasure Map for retrieval",
            type=click.STRING,
            required=True))
    retrieval_kits = StringList(
        RetrievalKit(),
        click=click.option(
            '--retrieval-kits',
            '-r',
            help="Retrieval kits for reencryption",
            multiple=True,
            type=click.STRING,
            required=True,
            default=[]),
        required=True,
        load_only=True)
    alice_verifying_key = UmbralKey(
        required=True,
        load_only=True,
        click=click.option(
            '--alice-verifying-key',
            '-avk',
            help="Alice's verifying key as a hexadecimal string",
            type=click.STRING,
            required=True))
    bob_encrypting_key = UmbralKey(
        required=True,
        load_only=True,
        click=option_bob_encrypting_key())
    bob_verifying_key = UmbralKey(
        required=True,
        load_only=True,
        click=click.option(
            '--bob-verifying-key',
            '-bvk',
            help="Bob's verifying key as a hexadecimal string",
            type=click.STRING,
            required=True))

    # optional
    context = JSON(
        expected_type=dict,
        required=False,
        load_only=True,
        click=click.option(
            "--context",
            "-ctx",
            help="Context data for retrieval conditions",
            type=click.STRING,
            required=False,
        ),
    )

    # output
    retrieval_results = marshmallow_fields.List(
        marshmallow_fields.Nested(PRERetrievalOutcomeSchema), dump_only=True
    )

#
# TACo Endpoints
#


class DecryptOutcomeSchema(BaseSchema):
    """Schema for the result of /retrieve_cfrags endpoint."""

    encrypted_decryption_responses = marshmallow_fields.Dict(
        keys=UrsulaChecksumAddress(), values=EncryptedThresholdDecryptionResponseField()
    )
    errors = marshmallow_fields.Dict(
        keys=UrsulaChecksumAddress(), values=marshmallow_fields.String()
    )

    # maintain field declaration ordering
    class Meta:
        ordered = True


class Decrypt(BaseSchema):
    threshold = PositiveInteger(
        required=True,
        load_only=True,
        click=click.option(
            "--decryption-threshold",
            "-d",
            help="Threshold of decryption responses required",
            type=click.INT,
            required=True
        )
    )
    encrypted_decryption_requests = marshmallow_fields.Dict(
        keys=UrsulaChecksumAddress(),
        values=EncryptedThresholdDecryptionRequestField(),
        required=True,
        load_only=True,
        click=click.option(
            "--encrypted-decryption-requests",
            "-e",
            help="Encrypted decryption requests dictionary keyed by ursula checksum address",
            type=click.STRING,
            required=True,
        ),
    )
    timeout = PositiveInteger(
        required=False,
        load_only=True,
        click=click.option(
            "--timeout",
            "-t",
            help="Timeout for decryption operation",
            type=click.INT,
            required=False,
        ),
    )

    # output
    decryption_results = marshmallow_fields.Nested(DecryptOutcomeSchema, dump_only=True)

    @validates_schema
    def check_valid_threshold_and_requests(self, data, **kwargs):
        # TODO is this check a good thing? What about re-requests after failures?
        threshold = data.get("threshold")
        encrypted_decryption_requests = data.get("encrypted_decryption_requests")
        if len(encrypted_decryption_requests) < threshold:
            raise InvalidArgumentCombo(
                "Number of provided requests must be >= the expected threshold"
            )
