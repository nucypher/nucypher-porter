import json
import os
from base64 import b64encode

import pytest
from eth_utils import to_canonical_address
from nucypher_core import Address, MessageKit
from nucypher_core import RetrievalKit as RetrievalKitClass
from nucypher_core.umbral import SecretKey

from porter.fields.base import (
    JSON,
    Base64BytesRepresentation,
    JSONDict,
    PositiveInteger,
    String,
    StringList,
)
from porter.fields.exceptions import InvalidInputData
from porter.fields.retrieve import RetrievalKit
from porter.fields.umbralkey import UmbralKey
from porter.fields.ursula import UrsulaChecksumAddress


def test_ursula_checksum_address_field(get_random_checksum_address):
    ursula_checksum = get_random_checksum_address()
    other_address = get_random_checksum_address()

    assert ursula_checksum != other_address

    field = UrsulaChecksumAddress()
    serialized = field._serialize(value=ursula_checksum, attr=None, obj=None)
    assert serialized == ursula_checksum
    assert serialized != other_address

    # test letter case of address
    serialized = field._serialize(value=ursula_checksum.lower(), attr=None, obj=None)
    assert serialized == ursula_checksum
    assert serialized != ursula_checksum.lower()
    serialized = field._serialize(value=ursula_checksum.upper(), attr=None, obj=None)
    assert serialized == ursula_checksum
    assert serialized != ursula_checksum.lower()

    with pytest.raises(InvalidInputData):
        field._serialize(value="0xdeadbeef", attr=None, obj=None)

    deserialized = field._deserialize(value=serialized, attr=None, data=None)
    assert deserialized == ursula_checksum

    field._deserialize(value=ursula_checksum, attr=None, data=None)
    field._deserialize(value=ursula_checksum.lower(), attr=None, data=None)
    field._deserialize(value=ursula_checksum.upper(), attr=None, data=None)
    field._deserialize(value=other_address, attr=None, data=None)
    field._deserialize(value=other_address.lower(), attr=None, data=None)
    field._deserialize(value=other_address.upper(), attr=None, data=None)

    with pytest.raises(InvalidInputData):
        field._deserialize(value="0xdeadbeef", attr=None, data=None)


def test_ursula_checksum_address_string_list_field(get_random_checksum_address):
    ursula_1 = get_random_checksum_address()
    ursula_2 = get_random_checksum_address()
    ursula_3 = get_random_checksum_address()
    ursula_4 = get_random_checksum_address()

    assert ursula_1 != ursula_2
    assert ursula_2 != ursula_3
    assert ursula_3 != ursula_4

    field = StringList(UrsulaChecksumAddress)

    deserialized = field._deserialize(value=f"{ursula_1},{ursula_2},{ursula_3},{ursula_4}", attr=None, data=None)
    assert deserialized == [ursula_1, ursula_2, ursula_3, ursula_4]

    # list instead
    data = [ursula_1, ursula_2, ursula_3, ursula_4]
    deserialized = field._deserialize(value=data, attr=None, data=None)
    assert deserialized == data

    # single entry
    deserialized = field._deserialize(value=f"{ursula_1}", attr=None, data=None)
    assert deserialized == [ursula_1]

    deserialized = field._deserialize(value=[ursula_1], attr=None, data=None)
    assert deserialized == [ursula_1]

    with pytest.raises(InvalidInputData):
        field._deserialize(value="0xdeadbeef", attr=None, data=None)

    with pytest.raises(InvalidInputData):
        field._deserialize(value=f"{ursula_1},{ursula_2},{ursula_3},{ursula_4},0xdeadbeef", attr=None, data=None)


def test_retrieval_kit_field(get_random_checksum_address):
    field = RetrievalKit()

    def run_tests_on_kit(kit: RetrievalKitClass):
        serialized = field._serialize(value=kit, attr=None, obj=None)
        assert serialized == b64encode(bytes(kit)).decode()

        deserialized = field._deserialize(value=serialized, attr=None, data=None)
        assert isinstance(deserialized, RetrievalKitClass)
        assert deserialized.capsule == kit.capsule
        assert deserialized.queried_addresses == kit.queried_addresses

    # kit with list of ursulas
    encrypting_key = SecretKey.random().public_key()
    capsule = MessageKit(encrypting_key, b'testing retrieval kit with 2 ursulas').capsule
    ursulas = [get_random_checksum_address(), get_random_checksum_address()]
    run_tests_on_kit(kit=RetrievalKitClass(capsule, {Address(to_canonical_address(ursula)) for ursula in ursulas}))

    # kit with no ursulas
    encrypting_key = SecretKey.random().public_key()
    capsule = MessageKit(policy_encrypting_key=encrypting_key, plaintext=b'testing retrieval kit with no ursulas').capsule
    run_tests_on_kit(kit=RetrievalKitClass(capsule, set()))

    with pytest.raises(InvalidInputData):
        field._deserialize(value=b"non_base_64_data", attr=None, data=None)

    with pytest.raises(InvalidInputData):
        field._deserialize(value=b64encode(b"invalid_retrieval_kit_bytes").decode(), attr=None, data=None)


def test_umbral_key():
    field = UmbralKey()

    umbral_pub_key = SecretKey.random().public_key()
    other_umbral_pub_key = SecretKey.random().public_key()

    serialized = field._serialize(value=umbral_pub_key, attr=None, obj=None)
    assert serialized == umbral_pub_key.to_compressed_bytes().hex()
    assert serialized != other_umbral_pub_key.to_compressed_bytes().hex()

    deserialized = field._deserialize(value=serialized, attr=None, data=None)
    assert deserialized == umbral_pub_key
    assert deserialized != other_umbral_pub_key

    with pytest.raises(InvalidInputData):
        field._deserialize(value=b"PublicKey".hex(), attr=None, data=None)


def test_positive_integer_field():
    field = PositiveInteger()

    field._validate(value=1)
    field._validate(value=10000)
    field._validate(value=1234567890)
    field._validate(value=22)

    invalid_values = [0, -1, -2, -10, -1000000, -12312311]
    for invalid_value in invalid_values:
        with pytest.raises(InvalidInputData):
            field._validate(value=invalid_value)


def test_string_list_field():
    field = StringList(String)

    data = 'Cornsilk,November,Sienna,India'
    deserialized = field._deserialize(value=data, attr=None, data=None)
    assert deserialized == ['Cornsilk', 'November', 'Sienna', 'India']

    data = ['Cornsilk', 'November', 'Sienna', 'India']
    deserialized = field._deserialize(value=data, attr=None, data=None)
    assert deserialized == data


def test_base64_representation_field():
    field = Base64BytesRepresentation()

    data = b"man in the arena"
    serialized = field._serialize(value=data, attr=None, obj=None)
    assert serialized == b64encode(data).decode()

    deserialized = field._deserialize(value=serialized, attr=None, data=None)
    assert deserialized == data

    with pytest.raises(InvalidInputData):
        # attempt to serialize a non-serializable object
        field._serialize(value=Exception("non-serializable"), attr=None, obj=None)

    with pytest.raises(InvalidInputData):
        # attempt to deserialize none base64 data
        field._deserialize(value=b"raw bytes with non base64 chars ?&^%", attr=None, data=None)


def test_json_field():
    # test data
    dict_data = {
        "domain": {"name": "tdec", "version": 1, "chainId": 1, "salt": "blahblahblah"},
        "message": {
            "address": "0x03e75d7dd38cce2e20ffee35ec914c57780a8e29",
            "blockNumber": 15440685,
            "blockHash": "0x2220da8b777767df526acffd5375ebb340fc98e53c1040b25ad1a8119829e3bd",
        },
    }
    list_data = [12.5, 1.2, 4.3]
    str_data = "Everything in the universe has a rhythm, everything dances."  # -- Maya Angelou
    num_data = 1234567890
    bool_data = True
    float_data = 2.35

    # test serialization/deserialization of data - no expected type specified
    test_data = [dict_data, list_data, str_data, num_data, bool_data, float_data]
    field = JSON()
    for d in test_data:
        serialized = field._serialize(value=d, attr=None, obj=None)
        assert serialized == json.dumps(d)

        deserialized = field._deserialize(value=serialized, attr=None, data=None)
        assert deserialized == d

    with pytest.raises(InvalidInputData):
        # attempt to serialize non-json serializable object
        field._serialize(value=Exception("non-serializable"), attr=None, obj=None)

    with pytest.raises(InvalidInputData):
        # attempt to deserialize invalid data
        field._deserialize(
            value=b"raw bytes", attr=None, data=None
        )

    # test expected type enforcement
    test_types = [type(d) for d in test_data]
    for expected_type in test_types:
        field = JSON(expected_type=expected_type)
        for d in test_data:
            if type(d) == expected_type:
                # serialization/deserialization should work
                serialized = field._serialize(value=d, attr=None, obj=None)
                assert serialized == json.dumps(d)

                deserialized = field._deserialize(value=serialized, attr=None, data=None)
                assert deserialized == d
            else:
                # serialization/deserialization should fail
                with pytest.raises(InvalidInputData):
                    # attempt to serialize non-json serializable object
                    field._serialize(d, attr=None, obj=None)

                with pytest.raises(InvalidInputData):
                    # attempt to deserialize invalid data
                    field._deserialize(value=json.dumps(d), attr=None, data=None)


def test_cbd_json_dict_field(get_random_checksum_address):
    # test data
    original_data = {}
    expected_serialized_result = {}
    num_decryption_requests = 5
    for i in range(0, 5):
        ursula_checksum_address = get_random_checksum_address()
        encrypted_decryption_request = os.urandom(32)
        original_data[ursula_checksum_address] = encrypted_decryption_request
        expected_serialized_result[ursula_checksum_address] = b64encode(
            encrypted_decryption_request
        ).decode()

    # mimic usage for CBD
    field = JSONDict(keys=UrsulaChecksumAddress(), values=Base64BytesRepresentation())
    serialized = field._serialize(value=original_data, attr=None, obj=None)
    assert serialized == json.dumps(expected_serialized_result)

    deserialized = field._deserialize(value=serialized, attr=None, data=None)
    assert deserialized == original_data

    with pytest.raises(InvalidInputData):
        # attempt to deserialize invalid key; must be checksum address
        json_to_deserialize = json.dumps({"a": b64encode(os.urandom(32)).decode()})
        field._deserialize(value=json_to_deserialize, attr=None, data=None)

    with pytest.raises(InvalidInputData):
        # attempt to deserialize invalid value; must be base64 string
        json_to_deserialize = json.dumps({get_random_checksum_address(): 1})
        field._deserialize(value=json_to_deserialize, attr=None, data=None)

    with pytest.raises(InvalidInputData):
        # attempt to deserialize non-dict object
        json_to_deserialize = json.dumps({get_random_checksum_address(): 1})
        field._deserialize("the hills are alive...", attr=None, data=None)

    with pytest.raises(InvalidInputData):
        # non-dict object
        field._serialize(value=[1, 2, 3], attr=None, obj=None)

    with pytest.raises(InvalidInputData):
        # attempt to serialize invalid key; must be checksum address
        field._serialize(value={"a": os.urandom(32)}, attr=None, obj=None)
