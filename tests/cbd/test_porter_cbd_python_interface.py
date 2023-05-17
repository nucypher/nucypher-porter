import json

from ferveo_py import (
    Ciphertext,
    DecryptionShareSimple,
    combine_decryption_shares_simple,
    decrypt_with_shared_secret,
)
from nucypher.crypto.ferveo.dkg import FerveoVariant
from nucypher_core import Conditions, ThresholdDecryptionRequest
from nucypher_core.umbral import SecretKey


def test_cbd_decryption(porter, dkg_setup, dkg_encrypted_data):
    ritual_id, public_key, cohort, params, threshold = dkg_setup
    ciphertext, expected_plaintext, conditions = dkg_encrypted_data

    decryption_request = ThresholdDecryptionRequest(
        id=ritual_id,
        variant=int(FerveoVariant.SIMPLE.value),
        ciphertext=ciphertext,
        conditions=Conditions(json.dumps(conditions)),
    )

    response_sk = SecretKey.random()

    encrypted_decryption_requests = {}
    for ursula in cohort:
        request_encrypting_key = (
            ursula.threshold_request_power.get_pubkey_from_ritual_id(ritual_id)
        )
        encrypted_decryption_requests[
            ursula.checksum_address
        ] = decryption_request.encrypt(
            request_encrypting_key=request_encrypting_key,
            response_encrypting_key=response_sk.public_key(),
        )

    cbd_outcome = porter.cbd_decrypt(
        threshold=threshold, encrypted_decryption_requests=encrypted_decryption_requests
    )

    # sufficient successes
    assert len(cbd_outcome.encrypted_decryption_responses) >= threshold

    # no errors
    assert len(cbd_outcome.errors) == 0

    cohort_addresses = [ursula.checksum_address for ursula in cohort]

    decryption_shares = []
    for (
        ursula_address,
        encrypted_decryption_response,
    ) in cbd_outcome.encrypted_decryption_responses.items():
        assert ursula_address in cohort_addresses
        decryption_response = encrypted_decryption_response.decrypt(sk=response_sk)
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
    # errors - invalid encrypting key used for request
    #
    random_public_key = SecretKey.random().public_key()
    encrypted_decryption_requests = {}
    for ursula in cohort:
        encrypted_decryption_requests[
            ursula.checksum_address
        ] = decryption_request.encrypt(
            request_encrypting_key=random_public_key,
            response_encrypting_key=response_sk.public_key(),
        )

    cbd_outcome = porter.cbd_decrypt(
        threshold=threshold, encrypted_decryption_requests=encrypted_decryption_requests
    )

    # sufficient successes
    assert len(cbd_outcome.encrypted_decryption_responses) == 0

    # no errors
    assert len(cbd_outcome.errors) == len(cohort)  # all ursulas fail
