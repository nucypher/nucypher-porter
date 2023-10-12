import pytest
from eth_utils import to_checksum_address
from nucypher_core import SessionStaticSecret, ThresholdDecryptionRequest
from nucypher_core.ferveo import FerveoVariant

from porter.fields.exceptions import InvalidArgumentCombo, InvalidInputData
from porter.fields.taco import (
    EncryptedThresholdDecryptionRequestField,
    EncryptedThresholdDecryptionResponseField,
)
from porter.main import Porter
from porter.schema import TACoDecrypt, TACoDecryptOutcomeSchema


def test_taco_decrypt(
    porter, dkg_setup, dkg_encrypted_data, get_random_checksum_address
):
    ritual_id, public_key, cohort, threshold = dkg_setup
    threshold_message_kit, expected_plaintext = dkg_encrypted_data

    taco_decrypt_schema = TACoDecrypt()

    decryption_request = ThresholdDecryptionRequest(
        ritual_id=ritual_id,
        variant=FerveoVariant.Simple,
        ciphertext_header=threshold_message_kit.ciphertext_header,
        acp=threshold_message_kit.acp,
        context=None,
    )

    requester_secret_key = SessionStaticSecret.random()

    encrypted_request_field = EncryptedThresholdDecryptionRequestField()
    encrypted_decryption_requests = {}
    for ursula in cohort:
        ursula_decryption_request_static_key = (
            ursula.threshold_request_power.get_pubkey_from_ritual_id(ritual_id)
        )
        shared_secret = requester_secret_key.derive_shared_secret(
            ursula_decryption_request_static_key
        )
        encrypted_decryption_request = decryption_request.encrypt(
            shared_secret=shared_secret,
            requester_public_key=requester_secret_key.public_key(),
        )
        encrypted_decryption_requests[
            ursula.checksum_address
        ] = encrypted_request_field._serialize(
            value=encrypted_decryption_request, attr=None, obj=None
        )

    # no args
    with pytest.raises(InvalidInputData):
        taco_decrypt_schema.load({})

    # missing required args
    with pytest.raises(InvalidInputData):
        request_data = {"threshold": threshold}
        taco_decrypt_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "encrypted_decryption_requests": encrypted_decryption_requests,
        }
        taco_decrypt_schema.load(request_data)

    # invalid param names
    with pytest.raises(InvalidInputData):
        request_data = {
            "dkg_threshold": threshold,
            "encrypted_decryption_requests": encrypted_decryption_requests,
        }
        taco_decrypt_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": threshold,
            "encrypted_dec_requests": encrypted_decryption_requests,
        }
        taco_decrypt_schema.load(request_data)

    # invalid param types
    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": "threshold? we don't need no stinking threshold",
            "encrypted_decryption_requests": encrypted_decryption_requests,
        }
        taco_decrypt_schema.load(request_data)

    # invalid param combination
    with pytest.raises(InvalidArgumentCombo):
        request_data = {
            "threshold": len(encrypted_decryption_requests)
            + 1,  # threshold larger than number of requests
            "encrypted_decryption_requests": encrypted_decryption_requests,
        }
        taco_decrypt_schema.load(request_data)

    # simple schema successful load
    request_data = {
        "threshold": threshold,
        "encrypted_decryption_requests": encrypted_decryption_requests,
    }
    taco_decrypt_schema.load(request_data)

    # actual outcomes
    encrypted_decryption_requests = {}
    for ursula in cohort:
        ursula_decryption_request_static_key = (
            ursula.threshold_request_power.get_pubkey_from_ritual_id(ritual_id)
        )
        shared_secret = requester_secret_key.derive_shared_secret(
            ursula_decryption_request_static_key
        )
        encrypted_decryption_request = decryption_request.encrypt(
            shared_secret=shared_secret,
            requester_public_key=requester_secret_key.public_key(),
        )
        encrypted_decryption_requests[
            ursula.checksum_address
        ] = encrypted_decryption_request

    taco_decrypt_outcome = porter.taco_decrypt(
        threshold=threshold, encrypted_decryption_requests=encrypted_decryption_requests
    )

    assert len(taco_decrypt_outcome.errors) == 0, f"{taco_decrypt_outcome.errors}"
    assert len(taco_decrypt_outcome.encrypted_decryption_responses) >= threshold

    taco_decrypt_outcome_schema = TACoDecryptOutcomeSchema()
    outcome_json = taco_decrypt_outcome_schema.dump(taco_decrypt_outcome)
    output = taco_decrypt_schema.dump(obj={"decryption_results": taco_decrypt_outcome})
    assert (
        len(output["decryption_results"]["encrypted_decryption_responses"]) >= threshold
    )
    assert (
        output["decryption_results"]["encrypted_decryption_responses"]
        == outcome_json["encrypted_decryption_responses"]
    )
    encrypted_response_field = EncryptedThresholdDecryptionResponseField()
    for (
        ursula_checksum_address,
        encrypted_decryption_response,
    ) in taco_decrypt_outcome.encrypted_decryption_responses.items():
        assert output["decryption_results"]["encrypted_decryption_responses"][
            ursula_checksum_address
        ] == encrypted_response_field._serialize(
            value=encrypted_decryption_response, attr=None, obj=None
        )

    assert len(output["decryption_results"]["errors"]) == 0
    assert output["decryption_results"]["errors"] == outcome_json["errors"]

    assert output == {"decryption_results": outcome_json}

    # now include errors
    errors = {}
    for i in range(len(cohort) - threshold, len(cohort)):
        ursula_checksum_address = to_checksum_address(cohort[i].checksum_address)
        errors[ursula_checksum_address] = f"Error Message {i}"

    faked_taco_decrypt_outcome = Porter.TACoDecryptOutcome(
        encrypted_decryption_responses=taco_decrypt_outcome.encrypted_decryption_responses,
        errors=errors,
    )
    faked_outcome_json = taco_decrypt_outcome_schema.dump(faked_taco_decrypt_outcome)
    output = taco_decrypt_schema.dump(
        obj={"decryption_results": faked_taco_decrypt_outcome}
    )
    assert (
        len(output["decryption_results"]["encrypted_decryption_responses"]) >= threshold
    )
    assert (
        output["decryption_results"]["encrypted_decryption_responses"]
        == faked_outcome_json["encrypted_decryption_responses"]
    )
    for (
        ursula_checksum_address,
        encrypted_decryption_response,
    ) in faked_taco_decrypt_outcome.encrypted_decryption_responses.items():
        assert output["decryption_results"]["encrypted_decryption_responses"][
            ursula_checksum_address
        ] == encrypted_response_field._serialize(
            value=encrypted_decryption_response, attr=None, obj=None
        )

    assert len(output["decryption_results"]["errors"]) == len(errors)
    assert output["decryption_results"]["errors"] == faked_outcome_json["errors"]
    for i in range(len(cohort) - threshold, len(cohort)):
        ursula_checksum_address = to_checksum_address(cohort[i].checksum_address)
        assert (
            output["decryption_results"]["errors"][ursula_checksum_address]
            == f"Error Message {i}"
        )

    assert output == {"decryption_results": faked_outcome_json}
