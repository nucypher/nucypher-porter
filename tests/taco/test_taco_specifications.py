import pytest
from eth_utils import to_checksum_address
from nucypher_core import (
    AAVersion,
    SessionStaticSecret,
    ThresholdDecryptionRequest,
    UserOperation,
    UserOperationSignatureRequest,
)
from nucypher_core.ferveo import FerveoVariant
from tests.constants import TESTERCHAIN_CHAIN_ID

from porter.fields.exceptions import InvalidArgumentCombo, InvalidInputData
from porter.fields.taco import (
    EncryptedThresholdDecryptionRequestField,
    EncryptedThresholdDecryptionResponseField,
    EncryptedThresholdSignatureRequestField,
    EncryptedThresholdSignatureResponseField,
)
from porter.main import Porter
from porter.schema import (
    Decrypt,
    DecryptOutcomeSchema,
    Sign,
    ThresholdSignatureOutcomeSchema,
)


def test_taco_decrypt_schema(dkg_setup, dkg_encrypted_data):
    ritual_id, public_key, cohort, threshold = dkg_setup
    threshold_message_kit, expected_plaintext = dkg_encrypted_data

    decrypt_schema = Decrypt()

    requester_secret_key = SessionStaticSecret.random()
    encrypted_decryption_requests = _generate_encrypted_decryption_requests(
        cohort, requester_secret_key, ritual_id, threshold_message_kit
    )

    encrypted_request_field = EncryptedThresholdDecryptionRequestField()
    for (
        checksum_address,
        encrypted_decryption_request,
    ) in encrypted_decryption_requests.items():
        encrypted_decryption_requests[checksum_address] = (
            encrypted_request_field._serialize(
                value=encrypted_decryption_request, attr=None, obj=None
            )
        )

    # no args
    with pytest.raises(InvalidInputData):
        decrypt_schema.load({})

    # missing required args
    with pytest.raises(InvalidInputData):
        request_data = {"threshold": threshold}
        decrypt_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "encrypted_decryption_requests": encrypted_decryption_requests,
        }
        decrypt_schema.load(request_data)

    # invalid param names
    with pytest.raises(InvalidInputData):
        request_data = {
            "dkg_threshold": threshold,
            "encrypted_decryption_requests": encrypted_decryption_requests,
        }
        decrypt_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": threshold,
            "encrypted_dec_requests": encrypted_decryption_requests,
        }
        decrypt_schema.load(request_data)

    # invalid param types
    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": "threshold? we don't need no stinking threshold",
            "encrypted_decryption_requests": encrypted_decryption_requests,
        }
        decrypt_schema.load(request_data)

    # invalid threshold value
    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": 0,
            "encrypted_decryption_requests": encrypted_decryption_requests,
        }
        decrypt_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": -1,
            "encrypted_decryption_requests": encrypted_decryption_requests,
        }
        decrypt_schema.load(request_data)

    # invalid timeout value
    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": threshold,
            "encrypted_decryption_requests": encrypted_decryption_requests,
            "timeout": "some number",
        }
        decrypt_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": threshold,
            "encrypted_decryption_requests": encrypted_decryption_requests,
            "timeout": 0,
        }
        decrypt_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": threshold,
            "encrypted_decryption_requests": encrypted_decryption_requests,
            "timeout": -1,
        }
        decrypt_schema.load(request_data)

    # invalid param combination
    with pytest.raises(InvalidArgumentCombo):
        request_data = {
            "threshold": (
                len(encrypted_decryption_requests) + 1
            ),  # threshold larger than number of requests
            "encrypted_decryption_requests": encrypted_decryption_requests,
        }
        decrypt_schema.load(request_data)

    # simple schema successful load
    request_data = {
        "threshold": threshold,
        "encrypted_decryption_requests": encrypted_decryption_requests,
    }
    decrypt_schema.load(request_data)


def test_taco_decrypt(porter, dkg_setup, dkg_encrypted_data):
    ritual_id, public_key, cohort, threshold = dkg_setup
    threshold_message_kit, expected_plaintext = dkg_encrypted_data

    decrypt_schema = Decrypt()

    requester_secret_key = SessionStaticSecret.random()

    encrypted_decryption_requests = _generate_encrypted_decryption_requests(
        cohort, requester_secret_key, ritual_id, threshold_message_kit
    )
    decrypt_outcome = porter.decrypt(
        threshold=threshold, encrypted_decryption_requests=encrypted_decryption_requests
    )

    assert len(decrypt_outcome.errors) == 0, f"{decrypt_outcome.errors}"
    assert len(decrypt_outcome.encrypted_decryption_responses) >= threshold

    decrypt_outcome_schema = DecryptOutcomeSchema()
    outcome_json = decrypt_outcome_schema.dump(decrypt_outcome)
    output = decrypt_schema.dump(obj={"decryption_results": decrypt_outcome})
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
    ) in decrypt_outcome.encrypted_decryption_responses.items():
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

    faked_decrypt_outcome = Porter.DecryptOutcome(
        encrypted_decryption_responses=decrypt_outcome.encrypted_decryption_responses,
        errors=errors,
    )
    faked_outcome_json = decrypt_outcome_schema.dump(faked_decrypt_outcome)
    output = decrypt_schema.dump(obj={"decryption_results": faked_decrypt_outcome})
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
    ) in faked_decrypt_outcome.encrypted_decryption_responses.items():
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


def _generate_encrypted_decryption_requests(
    cohort, requester_secret_key, ritual_id, threshold_message_kit
):
    decryption_request = ThresholdDecryptionRequest(
        ritual_id=ritual_id,
        variant=FerveoVariant.Simple,
        ciphertext_header=threshold_message_kit.ciphertext_header,
        acp=threshold_message_kit.acp,
        context=None,
    )

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
        encrypted_decryption_requests[ursula.checksum_address] = (
            encrypted_decryption_request
        )

    return encrypted_decryption_requests


@pytest.mark.parametrize("aa_version", [AAVersion.V08, AAVersion.MDT])
def test_taco_sign_schema(
    signing_cohort_setup, get_random_checksum_address, aa_version
):
    cohort_id, cohort, threshold = signing_cohort_setup

    sign_schema = Sign()

    user_op = UserOperation(
        sender=get_random_checksum_address(),
        nonce=0,
        call_data=b"12345",
        verification_gas_limit=100000,
        call_gas_limit=200000,
        pre_verification_gas=21000,
        max_priority_fee_per_gas=1000000000,
        max_fee_per_gas=2000000000,
    )
    signing_request = UserOperationSignatureRequest(
        user_op=user_op,
        aa_version=aa_version,
        chain_id=TESTERCHAIN_CHAIN_ID,
        cohort_id=cohort_id,
        context=None,
    )

    encrypted_signature_request_field = EncryptedThresholdSignatureRequestField()
    requester_secret_key = SessionStaticSecret.random()

    encrypted_signature_requests = _generate_encrypted_signature_requests(
        cohort, requester_secret_key, signing_request
    )
    for (
        checksum_address,
        encrypted_signature_request,
    ) in encrypted_signature_requests.items():
        encrypted_signature_requests[checksum_address] = (
            encrypted_signature_request_field._serialize(
                value=encrypted_signature_request, attr=None, obj=None
            )
        )

    # no args
    with pytest.raises(InvalidInputData):
        sign_schema.load({})

    # missing required args
    with pytest.raises(InvalidInputData):
        request_data = {"threshold": threshold}
        sign_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "encrypted_signing_requests": encrypted_signature_requests,
        }
        sign_schema.load(request_data)

    # invalid param names
    with pytest.raises(InvalidInputData):
        request_data = {
            "dkg_threshold": threshold,
            "encrypted_signing_requests": encrypted_signature_requests,
        }
        sign_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": threshold,
            "encrypted_sig_requests": encrypted_signature_requests,
        }
        sign_schema.load(request_data)

    # invalid param types
    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": "threshold? we don't need no stinking threshold",
            "encrypted_signing_requests": encrypted_signature_requests,
        }
        sign_schema.load(request_data)

    # invalid threshold value
    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": 0,
            "encrypted_signing_requests": encrypted_signature_requests,
        }
        sign_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": -1,
            "encrypted_signing_requests": encrypted_signature_requests,
        }
        sign_schema.load(request_data)

    # invalid timeout value
    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": threshold,
            "encrypted_signing_requests": encrypted_signature_requests,
            "timeout": "some number",
        }
        sign_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": threshold,
            "encrypted_signing_requests": encrypted_signature_requests,
            "timeout": 0,
        }
        sign_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": threshold,
            "encrypted_signing_requests": encrypted_signature_requests,
            "timeout": -1,
        }
        sign_schema.load(request_data)

    # invalid param combination
    with pytest.raises(InvalidArgumentCombo):
        request_data = {
            "threshold": (
                len(encrypted_signature_requests) + 1
            ),  # threshold larger than number of requests
            "encrypted_signing_requests": encrypted_signature_requests,
        }
        sign_schema.load(request_data)

    # simple schema successful load
    request_data = {
        "threshold": threshold,
        "encrypted_signing_requests": encrypted_signature_requests,
    }
    sign_schema.load(request_data)


@pytest.mark.parametrize(
    "signature_request",
    ["user_op_signature_request", "packed_user_op_signature_request"],
)
def test_taco_sign(porter, signing_cohort_setup, signature_request, request):
    signature_request = request.getfixturevalue(signature_request)
    cohort_id, cohort, threshold = signing_cohort_setup

    sign_schema = Sign()

    requester_secret_key = SessionStaticSecret.random()
    encrypted_signing_requests = _generate_encrypted_signature_requests(
        cohort, requester_secret_key, signature_request
    )
    signing_outcome = porter.sign(
        threshold=threshold, encrypted_signing_requests=encrypted_signing_requests
    )

    assert len(signing_outcome.errors) == 0, f"{signing_outcome.errors}"
    assert len(signing_outcome.encrypted_signature_responses) >= threshold

    sign_outcome_schema = ThresholdSignatureOutcomeSchema()
    outcome_json = sign_outcome_schema.dump(signing_outcome)
    output = sign_schema.dump(obj={"signing_results": signing_outcome})
    assert len(output["signing_results"]["encrypted_signature_responses"]) >= threshold
    assert (
        output["signing_results"]["encrypted_signature_responses"]
        == outcome_json["encrypted_signature_responses"]
    )

    encrypted_signature_response_field = EncryptedThresholdSignatureResponseField()
    for (
        ursula_checksum_address,
        encrypted_signature_response,
    ) in signing_outcome.encrypted_signature_responses.items():
        assert output["signing_results"]["encrypted_signature_responses"][
            ursula_checksum_address
        ] == encrypted_signature_response_field._serialize(
            value=encrypted_signature_response, attr=None, obj=None
        )

    assert len(output["signing_results"]["errors"]) == 0
    assert output["signing_results"]["errors"] == outcome_json["errors"]

    assert output == {"signing_results": outcome_json}

    # now include errors
    errors = {}
    for i in range(len(cohort) - threshold, len(cohort)):
        ursula_checksum_address = to_checksum_address(cohort[i].checksum_address)
        errors[ursula_checksum_address] = f"Error Message {i}"

    faked_signing_outcome = Porter.ThresholdSignatureOutcome(
        encrypted_signature_responses=signing_outcome.encrypted_signature_responses,
        errors=errors,
    )
    faked_outcome_json = sign_outcome_schema.dump(faked_signing_outcome)
    output = sign_schema.dump(obj={"signing_results": faked_signing_outcome})
    assert len(output["signing_results"]["encrypted_signature_responses"]) >= threshold
    assert (
        output["signing_results"]["encrypted_signature_responses"]
        == faked_outcome_json["encrypted_signature_responses"]
    )
    for (
        ursula_checksum_address,
        encrypted_signature_response,
    ) in faked_signing_outcome.encrypted_signature_responses.items():
        assert output["signing_results"]["encrypted_signature_responses"][
            ursula_checksum_address
        ] == encrypted_signature_response_field._serialize(
            value=encrypted_signature_response, attr=None, obj=None
        )

    assert len(output["signing_results"]["errors"]) == len(errors)
    assert output["signing_results"]["errors"] == faked_outcome_json["errors"]
    for i in range(len(cohort) - threshold, len(cohort)):
        ursula_checksum_address = to_checksum_address(cohort[i].checksum_address)
        assert (
            output["signing_results"]["errors"][ursula_checksum_address]
            == f"Error Message {i}"
        )

    assert output == {"signing_results": faked_outcome_json}


def _generate_encrypted_signature_requests(
    cohort, requester_secret_key, signature_request
):
    encrypted_signing_requests = {}
    for ursula in cohort:
        ursula_decryption_request_static_key = (
            ursula.signing_request_power.get_pubkey_from_ritual_id(
                signature_request.cohort_id
            )
        )
        shared_secret = requester_secret_key.derive_shared_secret(
            ursula_decryption_request_static_key
        )
        encrypted_signature_request = signature_request.encrypt(
            shared_secret=shared_secret,
            requester_public_key=requester_secret_key.public_key(),
        )
        encrypted_signing_requests[ursula.checksum_address] = (
            encrypted_signature_request
        )

    return encrypted_signing_requests
