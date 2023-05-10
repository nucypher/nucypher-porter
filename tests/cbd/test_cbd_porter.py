import json

from ferveo_py import (
    Ciphertext,
    DecryptionShareSimple,
    combine_decryption_shares_simple,
    decrypt_with_shared_secret,
)
from nucypher.crypto.ferveo.dkg import FerveoVariant
from nucypher_core import (
    Conditions,
    ThresholdDecryptionRequest,
    ThresholdDecryptionResponse,
)


def test_cbd_decryption(porter, dkg_setup, dkg_encrypted_data):
    ritual_id, public_key, cohort, params, threshold = dkg_setup
    ciphertext, expected_plaintext, conditions = dkg_encrypted_data

    decryption_request = ThresholdDecryptionRequest(
        id=ritual_id,
        variant=int(FerveoVariant.SIMPLE.value),
        ciphertext=ciphertext,
        conditions=Conditions(json.dumps(conditions)),
    )

    encrypted_decryption_requests = {
        ursula.checksum_address: bytes(decryption_request) for ursula in cohort
    }
    cbd_outcome = porter.cbd_decrypt(
        threshold=threshold, encrypted_decryption_requests=encrypted_decryption_requests
    )

    # sufficient successes
    assert len(cbd_outcome.decryption_responses) >= threshold

    # no errors
    assert len(cbd_outcome.errors) == 0

    ursula_addresses = [ursula.checksum_address for ursula in cohort]

    decryption_shares = []
    for ursula_address, response_bytes in cbd_outcome.decryption_responses.items():
        assert ursula_address in ursula_addresses
        assert len(response_bytes) > 0
        decryption_response = ThresholdDecryptionResponse.from_bytes(response_bytes)
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
