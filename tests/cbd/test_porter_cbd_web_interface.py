import json
import os
from base64 import b64encode, b64decode

from eth_utils import to_checksum_address
from ferveo_py import DecryptionShareSimple, combine_decryption_shares_simple, \
    decrypt_with_shared_secret, Ciphertext
from nucypher.crypto.ferveo.dkg import FerveoVariant
from nucypher_core import ThresholdDecryptionRequest, Conditions, ThresholdDecryptionResponse


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
        id=ritual_id,
        variant=int(FerveoVariant.SIMPLE.value),
        ciphertext=bytes(ciphertext),
        conditions=Conditions(json.dumps(conditions)),
    )
    encrypted_decryption_requests = {
        ursula.checksum_address: b64encode(bytes(decryption_request)).decode()
        for ursula in cohort
    }
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

    assert len(decryption_results['decryption_responses']) >= threshold

    cohort_addresses = [to_checksum_address(ursula.checksum_address) for ursula in cohort]

    errors = decryption_results["errors"]
    assert len(errors) == 0  # no errors

    decryption_responses = decryption_results["decryption_responses"]
    assert len(decryption_responses) >= threshold

    # check that the decryption performed was valid
    decryption_shares = []
    for ursula_address, response_bytes in decryption_responses.items():
        assert ursula_address in cohort_addresses
        assert len(response_bytes) > 0
        decryption_response = ThresholdDecryptionResponse.from_bytes(b64decode(response_bytes))
        decryption_share = DecryptionShareSimple.from_bytes(
            decryption_response.decryption_share
        )
        decryption_shares.append(decryption_share)

    shared_secret = combine_decryption_shares_simple(decryption_shares)
    conditions = json.dumps(conditions).encode()  # aad
    cleartext = decrypt_with_shared_secret(
        Ciphertext.from_bytes(ciphertext),
        conditions,  # aad
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
            data = b64encode(bytes(decryption_request)).decode()
        else:
            # invalid data
            data = b64encode(bytes(os.urandom(32))).decode()

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
    assert len(decryption_results['decryption_responses']) == (threshold - 1)
    errors = decryption_results["errors"]
    assert len(errors) == (len(cohort) - threshold + 1)
