from tests.utils.middleware import MockRestMiddleware
from porter.utils import retrieval_request_setup


def test_get_ursulas(blockchain_porter, blockchain_ursulas):
    # simple
    quantity = 4
    ursulas_info = blockchain_porter.get_ursulas(quantity=quantity)
    returned_ursula_addresses = {ursula_info.checksum_address for ursula_info in ursulas_info}
    assert len(returned_ursula_addresses) == quantity  # ensure no repeats

    blockchain_ursulas_list = list(blockchain_ursulas)

    # include specific ursulas
    include_ursulas = [blockchain_ursulas_list[0].checksum_address, blockchain_ursulas_list[1].checksum_address]
    ursulas_info = blockchain_porter.get_ursulas(quantity=quantity,
                                                 include_ursulas=include_ursulas)
    returned_ursula_addresses = {ursula_info.checksum_address for ursula_info in ursulas_info}
    assert len(returned_ursula_addresses) == quantity
    for address in include_ursulas:
        assert address in returned_ursula_addresses

    # exclude specific ursulas
    number_to_exclude = len(blockchain_ursulas_list) - 4
    exclude_ursulas = []
    for i in range(number_to_exclude):
        exclude_ursulas.append(blockchain_ursulas_list[i].checksum_address)
    ursulas_info = blockchain_porter.get_ursulas(quantity=quantity,
                                                 exclude_ursulas=exclude_ursulas)
    returned_ursula_addresses = {ursula_info.checksum_address for ursula_info in ursulas_info}
    assert len(returned_ursula_addresses) == quantity
    for address in exclude_ursulas:
        assert address not in returned_ursula_addresses

    # include and exclude
    include_ursulas = [blockchain_ursulas_list[0].checksum_address, blockchain_ursulas_list[1].checksum_address]
    exclude_ursulas = [blockchain_ursulas_list[2].checksum_address, blockchain_ursulas_list[3].checksum_address]
    ursulas_info = blockchain_porter.get_ursulas(quantity=quantity,
                                                 include_ursulas=include_ursulas,
                                                 exclude_ursulas=exclude_ursulas)
    returned_ursula_addresses = {ursula_info.checksum_address for ursula_info in ursulas_info}
    assert len(returned_ursula_addresses) == quantity
    for address in include_ursulas:
        assert address in returned_ursula_addresses
    for address in exclude_ursulas:
        assert address not in returned_ursula_addresses


def test_retrieve_cfrags(blockchain_porter,
                         random_blockchain_policy,
                         blockchain_bob,
                         blockchain_alice):
    # Setup
    network_middleware = MockRestMiddleware()
    # enact new random policy since idle_blockchain_policy/enacted_blockchain_policy already modified in previous tests
    enacted_policy = random_blockchain_policy.enact(network_middleware=network_middleware)
    retrieval_args, _ = retrieval_request_setup(enacted_policy, blockchain_bob, blockchain_alice)

    # use porter
    result = blockchain_porter.retrieve_cfrags(**retrieval_args)
    assert result


def test_retrieve_cfrags_with_context(blockchain_porter,
                                      random_blockchain_policy,
                                      blockchain_bob,
                                      blockchain_alice,
                                      random_context):
    # Setup
    network_middleware = MockRestMiddleware()
    # enact new random policy since idle_blockchain_policy/enacted_blockchain_policy already modified in previous tests
    enacted_policy = random_blockchain_policy.enact(network_middleware=network_middleware)
    retrieval_args, _ = retrieval_request_setup(enacted_policy,
                                                blockchain_bob,
                                                blockchain_alice,
                                                context=random_context)

    # use porter
    result = blockchain_porter.retrieve_cfrags(**retrieval_args)
    assert result
