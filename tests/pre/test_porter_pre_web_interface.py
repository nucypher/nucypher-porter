import json
from base64 import b64encode

from nucypher.characters.lawful import Enrico
from nucypher.crypto.powers import DecryptingPower
from nucypher.policy.kits import PolicyMessageKit, RetrievalResult
from nucypher_core import RetrievalKit

from porter.fields.base import JSON
from porter.fields.retrieve import RetrievalKit as RetrievalKitField
from porter.schema import PRERetrievalOutcomeSchema
from porter.utils import retrieval_params_decode_from_rest, retrieval_request_setup


def test_retrieve_cfrags(
    porter,
    porter_web_controller,
    enacted_policy,
    bob,
    alice,
    random_treasure_map_data,
    valid_user_address_context,
):
    # Send bad data to assert error return
    response = porter_web_controller.post(
        "/retrieve_cfrags", data=json.dumps({"bad": "input"})
    )
    assert response.status_code == 400

    # Setup
    original_message = (
        b"The paradox of education is precisely this - that as one begins to become "
        b"conscious one begins to examine the society in which "
        b"he is (they are) being educated."
    )  # - James Baldwin
    retrieve_cfrags_params, message_kits = retrieval_request_setup(
        enacted_policy,
        bob,
        alice,
        specific_messages=[original_message],
        encode_for_rest=True,
    )
    assert len(message_kits) == 1
    message_kit = message_kits[0]

    #
    # Success
    #
    response = porter_web_controller.post(
        "/retrieve_cfrags", data=json.dumps(retrieve_cfrags_params)
    )
    assert response.status_code == 200

    response_data = json.loads(response.data)
    retrieval_results = response_data["result"]["retrieval_results"]
    assert retrieval_results

    # expected results - can only compare length of results, ursulas are randomized to obtain cfrags
    retrieve_args = retrieval_params_decode_from_rest(retrieve_cfrags_params)
    expected_results = porter.retrieve_cfrags(**retrieve_args)
    assert len(retrieval_results) == len(expected_results)

    # check that the re-encryption performed was valid
    treasure_map = retrieve_args["treasure_map"]
    policy_message_kit = PolicyMessageKit.from_message_kit(
        message_kit=message_kit,
        policy_encrypting_key=enacted_policy.public_key,
        threshold=treasure_map.threshold,
    )
    assert len(retrieval_results) == 1
    field = PRERetrievalOutcomeSchema()
    cfrags = field.load(retrieval_results[0])["cfrags"]
    verified_cfrags = {}
    for ursula, cfrag in cfrags.items():
        # need to obtain verified cfrags (verified cfrags are not deserializable, only non-verified cfrags)
        verified_cfrag = cfrag.verify(
            capsule=policy_message_kit.message_kit.capsule,
            verifying_pk=alice.stamp.as_umbral_pubkey(),
            delegating_pk=enacted_policy.public_key,
            receiving_pk=bob.public_keys(DecryptingPower),
        )
        verified_cfrags[ursula] = verified_cfrag
    retrieval_result_object = RetrievalResult(cfrags=verified_cfrags)
    policy_message_kit = policy_message_kit.with_result(retrieval_result_object)

    assert policy_message_kit.is_decryptable_by_receiver()

    cleartext = bob._crypto_power.power_ups(
        DecryptingPower
    ).keypair.decrypt_message_kit(policy_message_kit)
    assert cleartext == original_message

    #
    # Try using multiple retrieval kits
    #
    multiple_retrieval_kits_params = dict(retrieve_cfrags_params)
    enrico = Enrico(encrypting_key=enacted_policy.public_key)
    retrieval_kit_1 = RetrievalKit.from_message_kit(
        enrico.encrypt_for_pre(b"The paradox of education is precisely this")
    )
    retrieval_kit_2 = RetrievalKit.from_message_kit(
        enrico.encrypt_for_pre(b"that as one begins to become conscious")
    )
    retrieval_kit_3 = RetrievalKit.from_message_kit(
        enrico.encrypt_for_pre(b"begins to examine the society in which")
    )
    retrieval_kit_4 = RetrievalKit.from_message_kit(
        enrico.encrypt_for_pre(b"he is (they are) being educated.")
    )
    retrieval_kit_field = RetrievalKitField()
    # use multiple retrieval kits and serialize for json
    multiple_retrieval_kits_params["retrieval_kits"] = [
        retrieval_kit_field._serialize(value=retrieval_kit_1, attr=None, obj=None),
        retrieval_kit_field._serialize(value=retrieval_kit_2, attr=None, obj=None),
        retrieval_kit_field._serialize(value=retrieval_kit_3, attr=None, obj=None),
        retrieval_kit_field._serialize(value=retrieval_kit_4, attr=None, obj=None),
    ]
    response = porter_web_controller.post(
        "/retrieve_cfrags", data=json.dumps(multiple_retrieval_kits_params)
    )
    assert response.status_code == 200

    response_data = json.loads(response.data)
    retrieval_results = response_data["result"]["retrieval_results"]
    assert retrieval_results
    assert len(retrieval_results) == 4
    for i in range(0, 4):
        assert len(retrieval_results[i]["cfrags"]) > 0
        assert len(retrieval_results[i]["errors"]) == 0

    #
    # Use context
    #
    context_field = JSON()
    multiple_retrieval_kits_params["context"] = context_field._serialize(
        valid_user_address_context, attr=None, obj=None
    )
    response = porter_web_controller.post(
        "/retrieve_cfrags", data=json.dumps(multiple_retrieval_kits_params)
    )
    assert response.status_code == 200

    response_data = json.loads(response.data)
    retrieval_results = response_data["result"]["retrieval_results"]
    assert retrieval_results
    assert len(retrieval_results) == 4

    #
    # Failure
    #
    failure_retrieve_cfrags_params = dict(retrieve_cfrags_params)
    # use encrypted treasure map
    _, random_treasure_map = random_treasure_map_data
    failure_retrieve_cfrags_params["treasure_map"] = b64encode(
        bytes(random_treasure_map)
    ).decode()
    response = porter_web_controller.post(
        "/retrieve_cfrags", data=json.dumps(failure_retrieve_cfrags_params)
    )
    assert response.status_code == 400  # invalid treasure map provided
