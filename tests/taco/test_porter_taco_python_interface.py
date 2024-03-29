import pytest
from nucypher_core import SessionStaticSecret, ThresholdDecryptionRequest
from nucypher_core.ferveo import (
    DecryptionShareSimple,
    FerveoVariant,
    combine_decryption_shares_simple,
)


@pytest.mark.parametrize("timeout", [None, 5, 7, 9])
def test_taco_decryption_success(porter, dkg_setup, dkg_encrypted_data, timeout):
    ritual_id, public_key, cohort, threshold = dkg_setup
    threshold_message_kit, expected_plaintext = dkg_encrypted_data

    decryption_request = ThresholdDecryptionRequest(
        ritual_id=ritual_id,
        variant=FerveoVariant.Simple,
        ciphertext_header=threshold_message_kit.ciphertext_header,
        acp=threshold_message_kit.acp,
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
        encrypted_decryption_requests[ursula.checksum_address] = (
            decryption_request.encrypt(
                shared_secret=shared_secret,
                requester_public_key=requester_secret_key.public_key(),
            )
        )
        shared_secrets[ursula.checksum_address] = shared_secret

    decrypt_outcome = porter.decrypt(
        threshold=threshold,
        encrypted_decryption_requests=encrypted_decryption_requests,
        timeout=timeout,
    )

    # sufficient successes
    assert len(decrypt_outcome.encrypted_decryption_responses) >= threshold

    # no errors
    assert len(decrypt_outcome.errors) == 0

    cohort_addresses = [ursula.checksum_address for ursula in cohort]

    decryption_shares = []
    for (
        ursula_address,
        encrypted_decryption_response,
    ) in decrypt_outcome.encrypted_decryption_responses.items():
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
    cleartext = threshold_message_kit.decrypt_with_shared_secret(combined_shares)
    assert bytes(cleartext) == expected_plaintext


@pytest.mark.parametrize("timeout", [None, 5, 7, 9])
def test_taco_decryption_failure(porter, dkg_setup, dkg_encrypted_data, timeout):
    ritual_id, public_key, cohort, threshold = dkg_setup
    threshold_message_kit, expected_plaintext = dkg_encrypted_data

    decryption_request = ThresholdDecryptionRequest(
        ritual_id=ritual_id,
        variant=FerveoVariant.Simple,
        ciphertext_header=threshold_message_kit.ciphertext_header,
        acp=threshold_message_kit.acp,
    )

    requester_secret_key = SessionStaticSecret.random()

    #
    # errors - invalid encrypting key used for request
    #
    random_public_key = SessionStaticSecret.random().public_key()
    shared_secret = requester_secret_key.derive_shared_secret(random_public_key)
    encrypted_decryption_requests = {}
    for ursula in cohort:
        encrypted_decryption_requests[ursula.checksum_address] = (
            decryption_request.encrypt(
                shared_secret=shared_secret,
                requester_public_key=requester_secret_key.public_key(),
            )
        )

    decrypt_outcome = porter.decrypt(
        threshold=threshold,
        encrypted_decryption_requests=encrypted_decryption_requests,
        timeout=timeout,
    )

    # sufficient successes
    assert len(decrypt_outcome.encrypted_decryption_responses) == 0

    # no errors
    assert len(decrypt_outcome.errors) == len(cohort)  # all ursulas fail
