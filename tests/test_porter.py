from porter.utils import retrieval_request_setup


def test_get_ursulas(federated_porter, federated_ursulas):
    # simple
    quantity = 4
    ursulas_info = federated_porter.get_ursulas(quantity=quantity)
    returned_ursula_addresses = {ursula_info.checksum_address for ursula_info in ursulas_info}
    assert len(returned_ursula_addresses) == quantity  # ensure no repeats

    federated_ursulas_list = list(federated_ursulas)

    # include specific ursulas
    include_ursulas = [federated_ursulas_list[0].checksum_address, federated_ursulas_list[1].checksum_address]
    ursulas_info = federated_porter.get_ursulas(quantity=quantity,
                                                include_ursulas=include_ursulas)
    returned_ursula_addresses = {ursula_info.checksum_address for ursula_info in ursulas_info}
    assert len(returned_ursula_addresses) == quantity
    for address in include_ursulas:
        assert address in returned_ursula_addresses

    # exclude specific ursulas
    number_to_exclude = len(federated_ursulas_list) - 4
    exclude_ursulas = []
    for i in range(number_to_exclude):
        exclude_ursulas.append(federated_ursulas_list[i].checksum_address)
    ursulas_info = federated_porter.get_ursulas(quantity=quantity,
                                                exclude_ursulas=exclude_ursulas)
    returned_ursula_addresses = {ursula_info.checksum_address for ursula_info in ursulas_info}
    assert len(returned_ursula_addresses) == quantity
    for address in exclude_ursulas:
        assert address not in returned_ursula_addresses

    # include and exclude
    include_ursulas = [federated_ursulas_list[0].checksum_address, federated_ursulas_list[1].checksum_address]
    exclude_ursulas = [federated_ursulas_list[2].checksum_address, federated_ursulas_list[3].checksum_address]
    ursulas_info = federated_porter.get_ursulas(quantity=quantity,
                                                include_ursulas=include_ursulas,
                                                exclude_ursulas=exclude_ursulas)
    returned_ursula_addresses = {ursula_info.checksum_address for ursula_info in ursulas_info}
    assert len(returned_ursula_addresses) == quantity
    for address in include_ursulas:
        assert address in returned_ursula_addresses
    for address in exclude_ursulas:
        assert address not in returned_ursula_addresses


def test_retrieve_cfrags(federated_porter,
                         federated_bob,
                         federated_alice,
                         enacted_federated_policy):
    # Setup
    retrieval_args, _ = retrieval_request_setup(enacted_federated_policy,
                                                federated_bob,
                                                federated_alice)

    result = federated_porter.retrieve_cfrags(**retrieval_args)

    assert result, "valid result returned"


def test_retrieve_cfrags_with_context(federated_porter,
                                      federated_bob,
                                      federated_alice,
                                      enacted_federated_policy,
                                      random_context):
    # Setup
    retrieval_args, _ = retrieval_request_setup(enacted_federated_policy,
                                                federated_bob,
                                                federated_alice,
                                                context=random_context)

    result = federated_porter.retrieve_cfrags(**retrieval_args)
    assert result, "valid result returned"
