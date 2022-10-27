import pytest
from nucypher_core import Address, HRAC, TreasureMap

from nucypher.crypto.powers import DecryptingPower


@pytest.fixture(scope='module')
def random_federated_treasure_map_data(federated_alice, federated_bob, federated_ursulas):

    label = b'policy label'
    threshold = 2
    shares = threshold + 1
    policy_key, kfrags = federated_alice.generate_kfrags(bob=federated_bob, label=label, threshold=threshold, shares=shares)
    hrac = HRAC(publisher_verifying_key=federated_alice.stamp.as_umbral_pubkey(),
                bob_verifying_key=federated_bob.stamp.as_umbral_pubkey(),
                label=label)

    assigned_kfrags = {
        Address(ursula.canonical_address): (ursula.public_keys(DecryptingPower), vkfrag)
        for ursula, vkfrag in zip(list(federated_ursulas)[:shares], kfrags)}

    random_treasure_map = TreasureMap(signer=federated_alice.stamp.as_umbral_signer(),
                                      hrac=hrac,
                                      policy_encrypting_key=policy_key,
                                      assigned_kfrags=assigned_kfrags,
                                      threshold=threshold)

    bob_key = federated_bob.public_keys(DecryptingPower)
    enc_treasure_map = random_treasure_map.encrypt(signer=federated_alice.stamp.as_umbral_signer(),
                                                   recipient_key=bob_key)

    yield bob_key, enc_treasure_map
