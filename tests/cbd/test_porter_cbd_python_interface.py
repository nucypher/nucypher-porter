import json

from nucypher.crypto.ferveo.dkg import FerveoVariant
from nucypher_core import Conditions, SessionStaticSecret, ThresholdDecryptionRequest
from nucypher_core.ferveo import (
    Ciphertext,
    DecryptionShareSimple,
    combine_decryption_shares_simple,
    decrypt_with_shared_secret,
)


def test_cbd_decryption(porter, dkg_setup, dkg_encrypted_data):
    ritual_id, public_key, cohort, params, threshold = dkg_setup
    ciphertext, expected_plaintext, conditions = dkg_encrypted_data

    decryption_request = ThresholdDecryptionRequest(
        ritual_id=ritual_id,
        variant=int(FerveoVariant.SIMPLE.value),
        ciphertext=ciphertext,
        conditions=Conditions(json.dumps(conditions)),
    )

    requester_secret_key = SessionStaticSecret.random()

    encrypted_decryption_requests = {}
    shared_secrets = {}
    for ursula in cohort:
        ursula_decryption_request_static_key = (
            ursula.threshold_request_power.get_pubkey_from_ritual_id(ritual_id)
        )
        shared_secret = requester_secret_key.derive_shared_secret(
            ursula_decryption_request_static_key
        )
        encrypted_decryption_requests[
            ursula.checksum_address
        ] = decryption_request.encrypt(
            shared_secret=shared_secret,
            requester_public_key=requester_secret_key.public_key(),
        )
        shared_secrets[ursula.checksum_address] = shared_secret

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
        shared_secret = shared_secrets[ursula_address]
        decryption_response = encrypted_decryption_response.decrypt(
            shared_secret=shared_secret
        )
        decryption_share = DecryptionShareSimple.from_bytes(
            decryption_response.decryption_share
        )
        decryption_shares.append(decryption_share)

    combined_shares = combine_decryption_shares_simple(decryption_shares)
    conditions = json.dumps(conditions).encode()  # aad
    cleartext = decrypt_with_shared_secret(
        ciphertext,
        conditions,  # aad
        combined_shares,
        params,  # dkg params
    )
    assert bytes(cleartext) == expected_plaintext

    #
    # errors - invalid encrypting key used for request
    #
    random_public_key = SessionStaticSecret.random().public_key()
    shared_secret = requester_secret_key.derive_shared_secret(random_public_key)
    encrypted_decryption_requests = {}
    for ursula in cohort:
        encrypted_decryption_requests[
            ursula.checksum_address
        ] = decryption_request.encrypt(
            shared_secret=shared_secret,
            requester_public_key=requester_secret_key.public_key(),
        )

    cbd_outcome = porter.cbd_decrypt(
        threshold=threshold, encrypted_decryption_requests=encrypted_decryption_requests
    )

    # sufficient successes
    assert len(cbd_outcome.encrypted_decryption_responses) == 0

    # no errors
    assert len(cbd_outcome.errors) == len(cohort)  # all ursulas fail
