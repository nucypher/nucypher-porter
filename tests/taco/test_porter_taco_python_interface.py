import random
from unittest.mock import ANY

import pytest
from nucypher.network.concurrency import SigningRequestClient, ThresholdDecryptionClient
from nucypher_core import (
    AAVersion,
    PackedUserOperationSignatureRequest,
    SessionStaticSecret,
    ThresholdDecryptionRequest,
    UserOperationSignatureRequest,
)
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


def test_taco_decryption_request_ordering(
    mocker, porter, dkg_setup, dkg_encrypted_data
):
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

    # make up fake latency stats
    latency_stats = {}
    for ursula in cohort:
        mock_latency = random.uniform(0.1, 5)
        porter.node_latency_collector.reset_stats(ursula.checksum_address)
        porter.node_latency_collector._update_stats(
            ursula.checksum_address, mock_latency
        )
        latency_stats[ursula.checksum_address] = mock_latency
        # average based on one data point
        assert (
            porter.node_latency_collector.get_average_latency_time(
                ursula.checksum_address
            )
            == mock_latency
        )

    expected_ursula_request_order = sorted(
        list(latency_stats.keys()), key=lambda node_address: latency_stats[node_address]
    )
    assert (
        porter.node_latency_collector.order_addresses_by_latency(
            list(latency_stats.keys())
        )
        == expected_ursula_request_order
    )

    value_factory_spy = mocker.spy(ThresholdDecryptionClient.RequestFactory, "__init__")

    decrypt_outcome = porter.decrypt(
        threshold=threshold,
        encrypted_decryption_requests=encrypted_decryption_requests,
    )

    # check that proper ordering of ursulas used for worker pool factory for requests
    value_factory_spy.assert_called_once_with(
        ANY,
        ursulas_to_contact=expected_ursula_request_order,
        batch_size=ANY,
        threshold=ANY,
    )

    # sufficient successes
    assert len(decrypt_outcome.encrypted_decryption_responses) >= threshold

    # no errors
    assert len(decrypt_outcome.errors) == 0


@pytest.mark.parametrize("timeout", [None, 5])
@pytest.mark.parametrize("aa_version", [AAVersion.V08, AAVersion.MDT])
@pytest.mark.parametrize(
    "signing_request", ["user_op_signature_request", "packed_user_op_signature_request"]
)
def test_taco_sign_success(
    porter, signing_cohort_setup, aa_version, signing_request, timeout, request
):
    cohort_id, cohort, threshold = signing_cohort_setup
    signing_request = request.getfixturevalue(signing_request)

    requester_secret_key = SessionStaticSecret.random()

    encrypted_signing_requests = {}
    shared_secrets = {}
    for ursula in cohort:
        ursula_signature_request_static_key = (
            ursula.signing_request_power.get_pubkey_from_ritual_id(cohort_id)
        )
        shared_secret = requester_secret_key.derive_shared_secret(
            ursula_signature_request_static_key
        )
        encrypted_signing_requests[ursula.checksum_address] = signing_request.encrypt(
            shared_secret=shared_secret,
            requester_public_key=requester_secret_key.public_key(),
        )
        shared_secrets[ursula.checksum_address] = shared_secret

    signing_outcome = porter.sign(
        threshold=threshold,
        encrypted_signing_requests=encrypted_signing_requests,
        timeout=timeout,
    )

    # no errors
    assert len(signing_outcome.errors) == 0, signing_outcome.errors

    # sufficient successes
    assert len(signing_outcome.encrypted_signature_responses) >= threshold

    cohort_checksum_addresses = [ursula.checksum_address for ursula in cohort]
    signer_addresses = {
        ursula.checksum_address: ursula.threshold_signing_power.account
        for ursula in cohort
    }
    common_hash = None
    for (
        ursula_address,
        encrypted_signature_response,
    ) in signing_outcome.encrypted_signature_responses.items():
        assert ursula_address in cohort_checksum_addresses
        shared_secret = shared_secrets[ursula_address]
        request_response = encrypted_signature_response.decrypt(
            shared_secret=shared_secret
        )
        assert request_response.signer == signer_addresses[ursula_address]
        assert len(request_response.signature) == 65  # ECDSA signature length
        assert request_response.signature_type == signing_request.signature_type
        if common_hash is None:
            common_hash = request_response.hash
        else:
            assert common_hash == request_response.hash


@pytest.mark.parametrize("timeout", [None, 5])
@pytest.mark.parametrize("aa_version", [AAVersion.V08, AAVersion.MDT])
@pytest.mark.parametrize(
    "signing_request", ["user_op_signature_request", "packed_user_op_signature_request"]
)
def test_taco_sign_failure(
    porter,
    signing_cohort_setup,
    aa_version,
    signing_request,
    timeout,
    signing_coordinator_agent,
    request,
):
    cohort_id, cohort, threshold = signing_cohort_setup
    signing_request_fixture = request.getfixturevalue(signing_request)
    requester_secret_key = SessionStaticSecret.random()

    if isinstance(signing_request_fixture, UserOperationSignatureRequest):
        # make the cohort inactive to simulate failure
        signing_request = UserOperationSignatureRequest(
            user_op=signing_request_fixture.user_op,
            aa_version=signing_request_fixture.aa_version,
            chain_id=signing_request_fixture.chain_id,
            cohort_id=999,
            context=None,
        )
    else:
        signing_request = PackedUserOperationSignatureRequest(
            packed_user_op=signing_request_fixture.packed_user_op,
            aa_version=signing_request_fixture.aa_version,
            chain_id=signing_request_fixture.chain_id,
            cohort_id=999,
            context=None,
        )

    encrypted_signing_requests = {}
    for ursula in cohort:
        ursula_signature_request_static_key = (
            ursula.signing_request_power.get_pubkey_from_ritual_id(cohort_id)
        )
        shared_secret = requester_secret_key.derive_shared_secret(
            ursula_signature_request_static_key
        )
        encrypted_signing_requests[ursula.checksum_address] = signing_request.encrypt(
            shared_secret=shared_secret,
            requester_public_key=requester_secret_key.public_key(),
        )

    # errors - invalid encrypting key used for request
    sign_outcome = porter.sign(
        threshold=threshold,
        encrypted_signing_requests=encrypted_signing_requests,
        timeout=timeout,
    )

    # no successes
    assert len(sign_outcome.encrypted_signature_responses) == 0

    # no errors
    assert len(sign_outcome.errors) == len(cohort)  # all ursulas fail


def test_taco_sign_request_ordering(
    mocker, porter, signing_cohort_setup, user_op_signature_request
):
    cohort_id, cohort, threshold = signing_cohort_setup
    requester_secret_key = SessionStaticSecret.random()

    encrypted_signing_requests = {}
    for ursula in cohort:
        ursula_signature_request_static_key = (
            ursula.signing_request_power.get_pubkey_from_ritual_id(cohort_id)
        )
        shared_secret = requester_secret_key.derive_shared_secret(
            ursula_signature_request_static_key
        )
        encrypted_signing_requests[ursula.checksum_address] = (
            user_op_signature_request.encrypt(
                shared_secret=shared_secret,
                requester_public_key=requester_secret_key.public_key(),
            )
        )

    # make up fake latency stats
    latency_stats = {}
    for ursula in cohort:
        mock_latency = random.uniform(0.1, 5)
        porter.node_latency_collector.reset_stats(ursula.checksum_address)
        porter.node_latency_collector._update_stats(
            ursula.checksum_address, mock_latency
        )
        latency_stats[ursula.checksum_address] = mock_latency
        # average based on one data point
        assert (
            porter.node_latency_collector.get_average_latency_time(
                ursula.checksum_address
            )
            == mock_latency
        )

    expected_ursula_request_order = sorted(
        list(latency_stats.keys()), key=lambda node_address: latency_stats[node_address]
    )
    assert (
        porter.node_latency_collector.order_addresses_by_latency(
            list(latency_stats.keys())
        )
        == expected_ursula_request_order
    )

    value_factory_spy = mocker.spy(SigningRequestClient.RequestFactory, "__init__")

    sign_outcome = porter.sign(
        threshold=threshold,
        encrypted_signing_requests=encrypted_signing_requests,
    )

    # check that proper ordering of ursulas used for worker pool factory for requests
    value_factory_spy.assert_called_once_with(
        ANY,
        ursulas_to_contact=expected_ursula_request_order,
        batch_size=ANY,
        threshold=ANY,
    )

    # sufficient successes
    assert len(sign_outcome.encrypted_signature_responses) >= threshold

    # no errors
    assert len(sign_outcome.errors) == 0
