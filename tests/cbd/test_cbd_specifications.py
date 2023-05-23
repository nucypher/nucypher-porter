import json
from base64 import b64encode

import pytest
from eth_utils import to_checksum_address
from nucypher.crypto.ferveo.dkg import FerveoVariant
from nucypher_core import Conditions, ThresholdDecryptionRequest

from porter.fields.exceptions import InvalidArgumentCombo, InvalidInputData
from porter.main import Porter
from porter.schema import CBDDecrypt, CBDDecryptionOutcomeSchema


def test_cbd_decrypt(
    porter, dkg_setup, dkg_encrypted_data, get_random_checksum_address
):
    ritual_id, public_key, cohort, _, threshold = dkg_setup
    ciphertext, expected_plaintext, conditions = dkg_encrypted_data

    cbd_decrypt_schema = CBDDecrypt()

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

    # no args
    with pytest.raises(InvalidInputData):
        cbd_decrypt_schema.load({})

    # missing required args
    with pytest.raises(InvalidInputData):
        request_data = {"threshold": threshold}
        cbd_decrypt_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "encrypted_decryption_requests": json.dumps(encrypted_decryption_requests)
        }
        cbd_decrypt_schema.load(request_data)

    # invalid param names
    with pytest.raises(InvalidInputData):
        request_data = {
            "dkg_threshold": threshold,
            "encrypted_decryption_requests": json.dumps(encrypted_decryption_requests),
        }
        cbd_decrypt_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": threshold,
            "encrypted_dec_requests": json.dumps(encrypted_decryption_requests),
        }
        cbd_decrypt_schema.load(request_data)

    # invalid param types
    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": "threshold? we don't need no stinking threshold",
            "encrypted_decryption_requests": json.dumps(encrypted_decryption_requests),
        }
        cbd_decrypt_schema.load(request_data)

    with pytest.raises(InvalidInputData):
        request_data = {
            "threshold": threshold,
            "encrypted_decryption_requests": encrypted_decryption_requests,  # not json string
        }
        cbd_decrypt_schema.load(request_data)

    # invalid param combination
    with pytest.raises(InvalidArgumentCombo):
        request_data = {
            "threshold": len(encrypted_decryption_requests)
            + 1,  # threshold larger than number of requests
            "encrypted_decryption_requests": json.dumps(encrypted_decryption_requests),
        }
        cbd_decrypt_schema.load(request_data)

    # simple schema successful load
    request_data = {
        "threshold": threshold,
        "encrypted_decryption_requests": json.dumps(encrypted_decryption_requests),
    }
    cbd_decrypt_schema.load(request_data)

    # actual outcomes
    encrypted_decryption_requests = {
        ursula.checksum_address: bytes(decryption_request)
        for ursula in cohort  # non-json version
    }
    cbd_outcome = porter.cbd_decrypt(
        threshold=threshold, encrypted_decryption_requests=encrypted_decryption_requests
    )
    cbd_outcome_schema = CBDDecryptionOutcomeSchema()

    assert len(cbd_outcome.decryption_responses) >= threshold
    assert len(cbd_outcome.errors) == 0

    outcome_json = cbd_outcome_schema.dump(cbd_outcome)
    output = cbd_decrypt_schema.dump(obj={"decryption_results": cbd_outcome})
    assert len(output["decryption_results"]["decryption_responses"]) >= threshold
    assert (
        output["decryption_results"]["decryption_responses"]
        == outcome_json["decryption_responses"]
    )
    for (
        ursula_checksum_address,
        decryption_response,
    ) in cbd_outcome.decryption_responses.items():
        assert (
            output["decryption_results"]["decryption_responses"][
                ursula_checksum_address
            ]
            == b64encode(decryption_response).decode()
        )

    assert len(output["decryption_results"]["errors"]) == 0
    assert output["decryption_results"]["errors"] == outcome_json["errors"]

    assert output == {"decryption_results": outcome_json}

    # now include errors
    errors = {}
    for i in range(len(cohort) - threshold, len(cohort)):
        ursula_checksum_address = to_checksum_address(cohort[i].checksum_address)
        errors[ursula_checksum_address] = f"Error Message {i}"

    faked_cbd_outcome = Porter.CBDDecryptionOutcome(
        decryption_responses=cbd_outcome.decryption_responses, errors=errors
    )
    faked_outcome_json = cbd_outcome_schema.dump(faked_cbd_outcome)
    output = cbd_decrypt_schema.dump(obj={"decryption_results": faked_cbd_outcome})
    assert len(output["decryption_results"]["decryption_responses"]) >= threshold
    assert (
        output["decryption_results"]["decryption_responses"]
        == faked_outcome_json["decryption_responses"]
    )
    for (
        ursula_checksum_address,
        decryption_response,
    ) in faked_cbd_outcome.decryption_responses.items():
        assert (
            output["decryption_results"]["decryption_responses"][
                ursula_checksum_address
            ]
            == b64encode(decryption_response).decode()
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
