import json
from base64 import b64decode

from eth_utils import to_checksum_address
from ferveo_py import (
    Ciphertext,
    DecryptionShareSimple,
    combine_decryption_shares_simple,
    decrypt_with_shared_secret,
)
from nucypher.crypto.ferveo.dkg import FerveoVariant
from nucypher_core import (
    Conditions,
    EncryptedThresholdDecryptionResponse,
    ThresholdDecryptionRequest,
)
from nucypher_core.umbral import SecretKey

from porter.fields.cbd import EncryptedThresholdDecryptionRequestField


def test_cbd_decrypt(
    porter,
    porter_web_controller,
    dkg_setup,
    dkg_encrypted_data
):
    # Send bad data to assert error return
    response = porter_web_controller.post(
        "/cbd_decrypt", data=json.dumps({"bad": "input"})
    )
    assert response.status_code == 400

    # Setup
    ritual_id, public_key, cohort, params, threshold = dkg_setup
    ciphertext, expected_plaintext, conditions = dkg_encrypted_data

    decryption_request = ThresholdDecryptionRequest(
        ritual_id=ritual_id,
        variant=int(FerveoVariant.SIMPLE.value),
        ciphertext=bytes(ciphertext),
        conditions=Conditions(json.dumps(conditions)),
    )

    response_sk = SecretKey.random()

    encrypted_request_field = EncryptedThresholdDecryptionRequestField()
    encrypted_decryption_requests = {}
    for ursula in cohort:
        request_encrypting_key = (
            ursula.threshold_request_power.get_pubkey_from_ritual_id(ritual_id)
        )
        encrypted_decryption_request = decryption_request.encrypt(
            request_encrypting_key=request_encrypting_key,
            response_encrypting_key=response_sk.public_key(),
        )
        encrypted_decryption_requests[
            ursula.checksum_address
        ] = encrypted_request_field._serialize(
            value=encrypted_decryption_request, attr=None, obj=None
        )

    request_data = {
        "threshold": threshold,
        "encrypted_decryption_requests": json.dumps(encrypted_decryption_requests),
    }

    #
    # Success
    #
    response = porter_web_controller.post(
        "/cbd_decrypt", data=json.dumps(request_data)
    )
    assert response.status_code == 200

    response_data = json.loads(response.data)

    decryption_results = response_data["result"]["decryption_results"]
    assert decryption_results

    assert len(decryption_results["encrypted_decryption_responses"]) >= threshold

    cohort_addresses = [to_checksum_address(ursula.checksum_address) for ursula in cohort]

    errors = decryption_results["errors"]
    assert len(errors) == 0  # no errors

    encrypted_decryption_responses = decryption_results[
        "encrypted_decryption_responses"
    ]
    assert len(encrypted_decryption_responses) >= threshold

    # check that the decryption performed was valid
    decryption_shares = []
    for ursula_address, response_bytes in encrypted_decryption_responses.items():
        assert ursula_address in cohort_addresses
        assert len(response_bytes) > 0
        encrypted_decryption_response = EncryptedThresholdDecryptionResponse.from_bytes(
            b64decode(response_bytes)
        )
        decryption_response = encrypted_decryption_response.decrypt(sk=response_sk)
        decryption_share = DecryptionShareSimple.from_bytes(
            decryption_response.decryption_share
        )
        decryption_shares.append(decryption_share)

    shared_secret = combine_decryption_shares_simple(decryption_shares)
    json_conditions = json.dumps(conditions).encode()  # aad
    cleartext = decrypt_with_shared_secret(
        Ciphertext.from_bytes(ciphertext),
        json_conditions,  # aad
        shared_secret,
        params,  # dkg params
    )
    assert bytes(cleartext) == expected_plaintext

    #
    # Errors (some invalid threshold decryption requests)
    #
    encrypted_decryption_requests = {}
    for i in range(0, len(cohort)):
        if i < threshold - 1:
            # less than threshold valid data
            request = decryption_request

        else:
            # invalid data
            request = ThresholdDecryptionRequest(
                ritual_id=999,  # rando invalid ritual id
                variant=int(FerveoVariant.SIMPLE.value),
                ciphertext=bytes(ciphertext),
                conditions=Conditions(json.dumps(conditions)),
            )

        encrypted_decryption_request = request.encrypt(
            request_encrypting_key=cohort[
                i
            ].threshold_request_power.get_pubkey_from_ritual_id(ritual_id=ritual_id),
            response_encrypting_key=response_sk.public_key(),
        )
        data = encrypted_request_field._serialize(
            value=encrypted_decryption_request, attr=None, obj=None
        )
        encrypted_decryption_requests[cohort[i].checksum_address] = data

    request_data = {
        "threshold": threshold,
        "encrypted_decryption_requests": json.dumps(encrypted_decryption_requests),
    }
    response = porter_web_controller.post(
        "/cbd_decrypt", data=json.dumps(request_data)
    )
    response_data = json.loads(response.data)

    decryption_results = response_data["result"]["decryption_results"]
    assert decryption_results
    assert len(decryption_results["encrypted_decryption_responses"]) == (threshold - 1)
    errors = decryption_results["errors"]
    assert len(errors) == (len(cohort) - (threshold - 1))
