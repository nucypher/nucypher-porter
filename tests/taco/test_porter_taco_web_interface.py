import json

import pytest
from eth_utils import to_checksum_address
from nucypher_core import (
    AAVersion,
    SessionStaticSecret,
    ThresholdDecryptionRequest,
    UserOperationSignatureRequest,
)
from nucypher_core.ferveo import (
    DecryptionShareSimple,
    FerveoVariant,
    combine_decryption_shares_simple,
)

from porter.fields.taco import (
    EncryptedThresholdDecryptionRequestField,
    EncryptedThresholdDecryptionResponseField,
    EncryptedThresholdSignatureRequestField,
    EncryptedThresholdSignatureResponseField,
)


def test_taco_decrypt_bad_input(porter_web_controller):
    # Send bad data to assert error return
    response = porter_web_controller.post("/decrypt", data=json.dumps({"bad": "input"}))
    assert response.status_code == 400


@pytest.mark.parametrize("timeout", [None, 5, 7, 9])
def test_taco_decrypt(
    porter, porter_web_controller, dkg_setup, dkg_encrypted_data, timeout
):
    # Setup
    ritual_id, public_key, cohort, threshold = dkg_setup
    threshold_message_kit, expected_plaintext = dkg_encrypted_data

    decryption_request = ThresholdDecryptionRequest(
        ritual_id=ritual_id,
        variant=FerveoVariant.Simple,
        ciphertext_header=threshold_message_kit.ciphertext_header,
        acp=threshold_message_kit.acp,
    )

    requester_secret_key = SessionStaticSecret.random()

    encrypted_request_field = EncryptedThresholdDecryptionRequestField()
    encrypted_decryption_requests = {}
    shared_secrets = {}
    for ursula in cohort:
        ursula_decryption_request_static_key = (
            ursula.decrypting_request_power.get_pubkey_from_id(ritual_id)
        )
        shared_secret = requester_secret_key.derive_shared_secret(
            ursula_decryption_request_static_key
        )
        encrypted_decryption_request = decryption_request.encrypt(
            shared_secret=shared_secret,
            requester_public_key=requester_secret_key.public_key(),
        )
        encrypted_decryption_requests[ursula.checksum_address] = (
            encrypted_request_field._serialize(
                value=encrypted_decryption_request, attr=None, obj=None
            )
        )
        shared_secrets[ursula.checksum_address] = shared_secret

    request_data = {
        "threshold": threshold,
        "encrypted_decryption_requests": encrypted_decryption_requests,
    }
    if timeout:
        request_data["timeout"] = timeout

    #
    # Success
    #
    response = porter_web_controller.post("/decrypt", data=json.dumps(request_data))
    assert response.status_code == 200

    response_data = json.loads(response.data)

    decryption_results = response_data["result"]["decryption_results"]
    assert decryption_results

    errors = decryption_results["errors"]
    assert len(errors) == 0, f"{errors}"  # no errors

    assert len(decryption_results["encrypted_decryption_responses"]) >= threshold

    cohort_addresses = [
        to_checksum_address(ursula.checksum_address) for ursula in cohort
    ]

    encrypted_decryption_responses = decryption_results[
        "encrypted_decryption_responses"
    ]
    assert len(encrypted_decryption_responses) >= threshold

    # check that the decryption performed was valid
    encrypted_threshold_decryption_response_field = (
        EncryptedThresholdDecryptionResponseField()
    )
    decryption_shares = []
    for ursula_address, response_bytes in encrypted_decryption_responses.items():
        assert ursula_address in cohort_addresses
        assert len(response_bytes) > 0
        encrypted_decryption_response = (
            encrypted_threshold_decryption_response_field._deserialize(
                value=response_bytes,
                attr=None,
                data=None,
            )
        )
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


@pytest.mark.parametrize("timeout", [None, 5, 10, 15])
def test_taco_decrypt_errors(
    porter, porter_web_controller, dkg_setup, dkg_encrypted_data, timeout
):
    # Setup
    ritual_id, public_key, cohort, threshold = dkg_setup
    threshold_message_kit, expected_plaintext = dkg_encrypted_data

    requester_secret_key = SessionStaticSecret.random()

    encrypted_request_field = EncryptedThresholdDecryptionRequestField()

    decryption_request = ThresholdDecryptionRequest(
        ritual_id=ritual_id,
        variant=FerveoVariant.Simple,
        ciphertext_header=threshold_message_kit.ciphertext_header,
        acp=threshold_message_kit.acp,
    )

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
                variant=FerveoVariant.Simple,
                ciphertext_header=threshold_message_kit.ciphertext_header,
                acp=threshold_message_kit.acp,
            )

        ursula_decryption_request_static_key = cohort[
            i
        ].decrypting_request_power.get_pubkey_from_id(ritual_id)
        shared_secret = requester_secret_key.derive_shared_secret(
            ursula_decryption_request_static_key
        )
        encrypted_decryption_request = request.encrypt(
            shared_secret=shared_secret,
            requester_public_key=requester_secret_key.public_key(),
        )
        data = encrypted_request_field._serialize(
            value=encrypted_decryption_request, attr=None, obj=None
        )
        encrypted_decryption_requests[cohort[i].checksum_address] = data

    request_data = {
        "threshold": threshold,
        "encrypted_decryption_requests": encrypted_decryption_requests,
    }
    if timeout:
        request_data["timeout"] = timeout

    response = porter_web_controller.post("/decrypt", data=json.dumps(request_data))
    response_data = json.loads(response.data)

    decryption_results = response_data["result"]["decryption_results"]
    assert decryption_results
    assert len(decryption_results["encrypted_decryption_responses"]) == (threshold - 1)
    errors = decryption_results["errors"]
    assert len(errors) == (len(cohort) - (threshold - 1))


def test_taco_sign_bad_input(porter_web_controller):
    # Send bad data to assert error return
    response = porter_web_controller.post("/sign", data=json.dumps({"bad": "input"}))
    assert response.status_code == 400


@pytest.mark.parametrize("timeout", [None, 5])
@pytest.mark.parametrize("aa_version", [AAVersion.V08, AAVersion.MDT])
@pytest.mark.parametrize(
    "signing_request", ["user_op_signature_request", "packed_user_op_signature_request"]
)
def test_taco_sign(
    porter,
    porter_web_controller,
    signing_cohort_setup,
    aa_version,
    signing_request,
    timeout,
    request,
):
    # Setup
    cohort_id, cohort, threshold = signing_cohort_setup
    signing_request = request.getfixturevalue(signing_request)
    requester_secret_key = SessionStaticSecret.random()

    encrypted_signature_request_field = EncryptedThresholdSignatureRequestField()
    encrypted_signing_requests = {}
    shared_secrets = {}
    for ursula in cohort:
        ursula_signature_request_static_key = (
            ursula.signing_request_power.get_pubkey_from_id(cohort_id)
        )
        shared_secret = requester_secret_key.derive_shared_secret(
            ursula_signature_request_static_key
        )
        shared_secrets[ursula.checksum_address] = shared_secret
        encrypted_signing_request = signing_request.encrypt(
            shared_secret=shared_secret,
            requester_public_key=requester_secret_key.public_key(),
        )
        encrypted_signing_requests[ursula.checksum_address] = (
            encrypted_signature_request_field._serialize(
                value=encrypted_signing_request, attr=None, obj=None
            )
        )

    request_data = {
        "threshold": threshold,
        "encrypted_signing_requests": encrypted_signing_requests,
    }
    if timeout:
        request_data["timeout"] = timeout

    #
    # Success
    #
    response = porter_web_controller.post("/sign", data=json.dumps(request_data))
    assert response.status_code == 200

    response_data = json.loads(response.data)

    signing_results = response_data["result"]["signing_results"]
    assert signing_results

    errors = signing_results["errors"]
    assert len(errors) == 0, f"{errors}"  # no errors

    assert len(signing_results["encrypted_signature_responses"]) >= threshold
    encrypted_signature_responses = signing_results["encrypted_signature_responses"]

    signature_response_field = EncryptedThresholdSignatureResponseField()
    cohort_checksum_addresses = [ursula.checksum_address for ursula in cohort]
    signer_addresses = {
        u.checksum_address: u.threshold_signing_power.account for u in cohort
    }
    common_hash = None
    for ursula_address, encrypted_response in encrypted_signature_responses.items():
        assert ursula_address in cohort_checksum_addresses
        encrypted_request_response = signature_response_field._deserialize(
            value=encrypted_response, attr=None, data=None
        )
        shared_secret = shared_secrets[ursula_address]
        request_response = encrypted_request_response.decrypt(
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
def test_taco_sign_errors(
    porter,
    porter_web_controller,
    signing_cohort_setup,
    aa_version,
    user_op_signature_request,
    timeout,
):
    # Setup
    cohort_id, cohort, threshold = signing_cohort_setup
    requester_secret_key = SessionStaticSecret.random()
    encrypted_signature_request_field = EncryptedThresholdSignatureRequestField()

    #
    # Errors (some invalid threshold signing requests)
    #
    encrypted_signing_requests = {}
    for i in range(0, len(cohort)):
        if i < threshold - 1:
            # less than threshold valid data
            request = user_op_signature_request

        else:
            # invalid data
            request = UserOperationSignatureRequest(
                user_op=user_op_signature_request.user_op,
                aa_version=user_op_signature_request.aa_version,
                chain_id=user_op_signature_request.chain_id,
                cohort_id=999,  # random invalid cohort id
                context=None,
            )

        ursula_signature_request_static_key = cohort[
            i
        ].signing_request_power.get_pubkey_from_id(cohort_id)
        shared_secret = requester_secret_key.derive_shared_secret(
            ursula_signature_request_static_key
        )
        encrypted_signing_request = request.encrypt(
            shared_secret=shared_secret,
            requester_public_key=requester_secret_key.public_key(),
        )
        encrypted_signing_requests[cohort[i].checksum_address] = (
            encrypted_signature_request_field._serialize(
                value=encrypted_signing_request, attr=None, obj=None
            )
        )

    request_data = {
        "threshold": threshold,
        "encrypted_signing_requests": encrypted_signing_requests,
    }
    if timeout:
        request_data["timeout"] = timeout

    response = porter_web_controller.post("/sign", data=json.dumps(request_data))
    response_data = json.loads(response.data)

    signing_results = response_data["result"]["signing_results"]
    assert signing_results
    assert len(signing_results["encrypted_signature_responses"]) == (threshold - 1)
    errors = signing_results["errors"]
    assert len(errors) == (len(cohort) - (threshold - 1))
