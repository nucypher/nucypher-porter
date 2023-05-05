from porter.utils import retrieval_request_setup


def test_get_ursulas(porter, ursulas):
    # simple
    quantity = 4
    ursulas_info = porter.get_ursulas(quantity=quantity)
    returned_ursula_addresses = {ursula_info.checksum_address for ursula_info in ursulas_info}
    assert len(returned_ursula_addresses) == quantity  # ensure no repeats

    ursulas_list = list(ursulas)

    # include specific ursulas
    include_ursulas = [ursulas_list[0].checksum_address, ursulas_list[1].checksum_address]
    ursulas_info = porter.get_ursulas(quantity=quantity,
                                      include_ursulas=include_ursulas)
    returned_ursula_addresses = {ursula_info.checksum_address for ursula_info in ursulas_info}
    assert len(returned_ursula_addresses) == quantity
    for address in include_ursulas:
        assert address in returned_ursula_addresses

    # exclude specific ursulas
    number_to_exclude = len(ursulas_list) - 4
    exclude_ursulas = []
    for i in range(number_to_exclude):
        exclude_ursulas.append(ursulas_list[i].checksum_address)
    ursulas_info = porter.get_ursulas(quantity=quantity,
                                      exclude_ursulas=exclude_ursulas)
    returned_ursula_addresses = {ursula_info.checksum_address for ursula_info in ursulas_info}
    assert len(returned_ursula_addresses) == quantity
    for address in exclude_ursulas:
        assert address not in returned_ursula_addresses

    # include and exclude
    include_ursulas = [ursulas_list[0].checksum_address, ursulas_list[1].checksum_address]
    exclude_ursulas = [ursulas_list[2].checksum_address, ursulas_list[3].checksum_address]
    ursulas_info = porter.get_ursulas(quantity=quantity,
                                      include_ursulas=include_ursulas,
                                      exclude_ursulas=exclude_ursulas)
    returned_ursula_addresses = {ursula_info.checksum_address for ursula_info in ursulas_info}
    assert len(returned_ursula_addresses) == quantity
    for address in include_ursulas:
        assert address in returned_ursula_addresses
    for address in exclude_ursulas:
        assert address not in returned_ursula_addresses


def test_retrieve_cfrags(porter,
                         bob,
                         alice,
                         enacted_policy):
    # Setup
    retrieval_args, _ = retrieval_request_setup(enacted_policy,
                                                bob,
                                                alice)

    result = porter.retrieve_cfrags(**retrieval_args)

    assert result, "valid result returned"


def test_retrieve_cfrags_with_context(porter,
                                      bob,
                                      alice,
                                      enacted_policy,
                                      valid_user_address_context):
    # Setup
    retrieval_args, _ = retrieval_request_setup(enacted_policy,
                                                bob,
                                                alice,
                                                context=valid_user_address_context)

    result = porter.retrieve_cfrags(**retrieval_args)
    assert result, "valid result returned"
