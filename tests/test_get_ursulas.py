import json

import pytest
from nucypher_core.umbral import SecretKey

from porter.fields.exceptions import InvalidArgumentCombo, InvalidInputData
from porter.main import Porter
from porter.schema import GetUrsulas, UrsulaInfoSchema


def test_get_ursulas_schema(get_random_checksum_address):
    #
    # Input i.e. load
    #

    # no args
    with pytest.raises(InvalidInputData):
        GetUrsulas().load({})

    quantity = 10
    required_data = {
        "quantity": quantity,
    }

    # required args
    GetUrsulas().load(required_data)

    # missing required args
    updated_data = {k: v for k, v in required_data.items() if k != "quantity"}
    with pytest.raises(InvalidInputData):
        GetUrsulas().load(updated_data)

    # optional components

    # only exclude
    updated_data = dict(required_data)
    exclude_ursulas = []
    for i in range(2):
        exclude_ursulas.append(get_random_checksum_address())
    updated_data["exclude_ursulas"] = exclude_ursulas
    GetUrsulas().load(updated_data)

    # only include
    updated_data = dict(required_data)
    include_ursulas = []
    for i in range(3):
        include_ursulas.append(get_random_checksum_address())
    updated_data["include_ursulas"] = include_ursulas
    GetUrsulas().load(updated_data)

    # both exclude and include
    updated_data = dict(required_data)
    updated_data["exclude_ursulas"] = exclude_ursulas
    updated_data["include_ursulas"] = include_ursulas
    GetUrsulas().load(updated_data)

    # both exclude and include and timeout
    updated_data = dict(required_data)
    updated_data["exclude_ursulas"] = exclude_ursulas
    updated_data["include_ursulas"] = include_ursulas
    updated_data["timeout"] = 20
    GetUrsulas().load(updated_data)

    # list input formatted as ',' separated strings
    updated_data = dict(required_data)
    updated_data["exclude_ursulas"] = ",".join(exclude_ursulas)
    updated_data["include_ursulas"] = ",".join(include_ursulas)
    data = GetUrsulas().load(updated_data)
    assert data["exclude_ursulas"] == exclude_ursulas
    assert data["include_ursulas"] == include_ursulas

    # single value as string cast to list
    updated_data = dict(required_data)
    updated_data["exclude_ursulas"] = exclude_ursulas[0]
    updated_data["include_ursulas"] = include_ursulas[0]
    data = GetUrsulas().load(updated_data)
    assert data["exclude_ursulas"] == [exclude_ursulas[0]]
    assert data["include_ursulas"] == [include_ursulas[0]]

    # invalid include entry
    updated_data = dict(required_data)
    updated_data["exclude_ursulas"] = exclude_ursulas
    updated_data["include_ursulas"] = list(include_ursulas)  # make copy to modify
    updated_data["include_ursulas"].append("0xdeadbeef")
    with pytest.raises(InvalidInputData):
        GetUrsulas().load(updated_data)

    # invalid exclude entry
    updated_data = dict(required_data)
    updated_data["exclude_ursulas"] = list(exclude_ursulas)  # make copy to modify
    updated_data["exclude_ursulas"].append("0xdeadbeef")
    updated_data["include_ursulas"] = include_ursulas
    with pytest.raises(InvalidInputData):
        GetUrsulas().load(updated_data)

    # too many ursulas to include
    updated_data = dict(required_data)
    too_many_ursulas_to_include = []
    while len(too_many_ursulas_to_include) <= quantity:
        too_many_ursulas_to_include.append(get_random_checksum_address())
    updated_data["include_ursulas"] = too_many_ursulas_to_include
    with pytest.raises(InvalidArgumentCombo):
        # number of ursulas to include exceeds quantity to sample
        GetUrsulas().load(updated_data)

    # include and exclude addresses are not mutually exclusive - include has common entry
    updated_data = dict(required_data)
    updated_data["exclude_ursulas"] = exclude_ursulas
    updated_data["include_ursulas"] = list(include_ursulas)  # make copy to modify
    updated_data["include_ursulas"].append(
        exclude_ursulas[0]
    )  # one address that overlaps
    with pytest.raises(InvalidArgumentCombo):
        # 1 address in both include and exclude lists
        GetUrsulas().load(updated_data)

    # include and exclude addresses are not mutually exclusive - exclude has common entry
    updated_data = dict(required_data)
    updated_data["exclude_ursulas"] = list(exclude_ursulas)  # make copy to modify
    updated_data["exclude_ursulas"].append(
        include_ursulas[0]
    )  # on address that overlaps
    updated_data["include_ursulas"] = include_ursulas
    with pytest.raises(InvalidArgumentCombo):
        # 1 address in both include and exclude lists
        GetUrsulas().load(updated_data)

    # invalid timeout value
    with pytest.raises(InvalidInputData):
        updated_data = dict(required_data)
        updated_data["exclude_ursulas"] = exclude_ursulas
        updated_data["timeout"] = "some number"
        GetUrsulas().load(updated_data)

    with pytest.raises(InvalidInputData):
        updated_data = dict(required_data)
        updated_data["exclude_ursulas"] = exclude_ursulas
        updated_data["include_ursulas"] = include_ursulas
        updated_data["timeout"] = 0
        GetUrsulas().load(updated_data)

    with pytest.raises(InvalidInputData):
        updated_data = dict(required_data)
        updated_data["exclude_ursulas"] = exclude_ursulas
        updated_data["include_ursulas"] = include_ursulas
        updated_data["timeout"] = -1
        GetUrsulas().load(updated_data)

    #
    # Output i.e. dump
    #
    ursulas_info = []
    expected_ursulas_info = []
    port = 11500
    for i in range(3):
        ursula_info = Porter.UrsulaInfo(
            get_random_checksum_address(),
            f"https://127.0.0.1:{port+i}",
            SecretKey.random().public_key(),
        )
        ursulas_info.append(ursula_info)

        # use schema to determine expected output (encrypting key gets changed to hex)
        expected_ursulas_info.append(UrsulaInfoSchema().dump(ursula_info))

    output = GetUrsulas().dump(obj={"ursulas": ursulas_info})
    assert output == {"ursulas": expected_ursulas_info}


@pytest.mark.parametrize("timeout", [None, 15, 20])
def test_get_ursulas_python_interface(porter, ursulas, timeout):
    # simple
    quantity = 4
    ursulas_info = porter.get_ursulas(quantity=quantity)
    returned_ursula_addresses = {
        ursula_info.checksum_address for ursula_info in ursulas_info
    }
    assert len(returned_ursula_addresses) == quantity  # ensure no repeats

    ursulas_list = list(ursulas)

    # include specific ursulas
    include_ursulas = [
        ursulas_list[0].checksum_address,
        ursulas_list[1].checksum_address,
    ]
    ursulas_info = porter.get_ursulas(
        quantity=quantity, include_ursulas=include_ursulas, timeout=timeout
    )
    returned_ursula_addresses = {
        ursula_info.checksum_address for ursula_info in ursulas_info
    }
    assert len(returned_ursula_addresses) == quantity
    for address in include_ursulas:
        assert address in returned_ursula_addresses

    # exclude specific ursulas
    number_to_exclude = len(ursulas_list) - 4
    exclude_ursulas = []
    for i in range(number_to_exclude):
        exclude_ursulas.append(ursulas_list[i].checksum_address)
    ursulas_info = porter.get_ursulas(
        quantity=quantity, exclude_ursulas=exclude_ursulas, timeout=timeout
    )
    returned_ursula_addresses = {
        ursula_info.checksum_address for ursula_info in ursulas_info
    }
    assert len(returned_ursula_addresses) == quantity
    for address in exclude_ursulas:
        assert address not in returned_ursula_addresses

    # include and exclude
    include_ursulas = [
        ursulas_list[0].checksum_address,
        ursulas_list[1].checksum_address,
    ]
    exclude_ursulas = [
        ursulas_list[2].checksum_address,
        ursulas_list[3].checksum_address,
    ]
    ursulas_info = porter.get_ursulas(
        quantity=quantity,
        include_ursulas=include_ursulas,
        exclude_ursulas=exclude_ursulas,
        timeout=timeout,
    )
    returned_ursula_addresses = {
        ursula_info.checksum_address for ursula_info in ursulas_info
    }
    assert len(returned_ursula_addresses) == quantity
    for address in include_ursulas:
        assert address in returned_ursula_addresses
    for address in exclude_ursulas:
        assert address not in returned_ursula_addresses

    # too many ursulas requested
    with pytest.raises(ValueError, match="Insufficient nodes"):
        porter.get_ursulas(quantity=len(ursulas) + 1)


@pytest.mark.parametrize("timeout", [None, 10, 20])
def test_get_ursulas_web_interface(porter_web_controller, ursulas, timeout):
    # Send bad data to assert error return
    response = porter_web_controller.get(
        "/get_ursulas", data=json.dumps({"bad": "input"})
    )
    assert response.status_code == 400

    quantity = 4
    ursulas_list = list(ursulas)
    include_ursulas = [
        ursulas_list[0].checksum_address,
        ursulas_list[1].checksum_address,
    ]
    exclude_ursulas = [
        ursulas_list[2].checksum_address,
        ursulas_list[3].checksum_address,
    ]

    get_ursulas_params = {
        "quantity": quantity,
        "include_ursulas": include_ursulas,
        "exclude_ursulas": exclude_ursulas,
    }

    if timeout:
        get_ursulas_params["timeout"] = timeout

    #
    # Success
    #
    response = porter_web_controller.get(
        "/get_ursulas", data=json.dumps(get_ursulas_params)
    )
    assert response.status_code == 200

    response_data = json.loads(response.data)
    ursulas_info = response_data["result"]["ursulas"]
    returned_ursula_addresses = {
        ursula_info["checksum_address"] for ursula_info in ursulas_info
    }  # ensure no repeats
    assert len(returned_ursula_addresses) == quantity
    for address in include_ursulas:
        assert address in returned_ursula_addresses
    for address in exclude_ursulas:
        assert address not in returned_ursula_addresses

    #
    # Test Query parameters
    #
    query_params = (
        f"/get_ursulas?quantity={quantity}"
        f'&include_ursulas={",".join(include_ursulas)}'
        f'&exclude_ursulas={",".join(exclude_ursulas)}'
    )
    if timeout:
        query_params += f"&timeout={timeout}"

    response = porter_web_controller.get(query_params)
    assert response.status_code == 200
    response_data = json.loads(response.data)
    ursulas_info = response_data["result"]["ursulas"]
    returned_ursula_addresses = {
        ursula_info["checksum_address"] for ursula_info in ursulas_info
    }  # ensure no repeats
    assert len(returned_ursula_addresses) == quantity
    for address in include_ursulas:
        assert address in returned_ursula_addresses
    for address in exclude_ursulas:
        assert address not in returned_ursula_addresses

    #
    # Failure case: too many ursulas requested
    #
    failed_ursula_params = dict(get_ursulas_params)
    failed_ursula_params["quantity"] = len(ursulas_list) + 1  # too many to get
    response = porter_web_controller.get(
        "/get_ursulas", data=json.dumps(failed_ursula_params)
    )
    assert response.status_code == 400
    assert "Insufficient nodes" in response.text
