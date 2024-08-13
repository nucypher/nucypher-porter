from typing import Iterable, Optional

import pytest
from eth_typing import ChecksumAddress
from nucypher.blockchain.eth.agents import (
    StakingProvidersReservoir,
    TACoApplicationAgent,
)
from nucypher.policy.payment import SubscriptionManagerPayment


@pytest.fixture(scope="module", autouse=True)
def mock_sample_reservoir(accounts, mock_contract_agency):
    def mock_reservoir(
        without: Optional[Iterable[ChecksumAddress]] = None, *args, **kwargs
    ):
        addresses = {
            address: 1
            for address in accounts.staking_providers_accounts
            if address not in without
        }
        return StakingProvidersReservoir(addresses)

    # TODO - this is needed for PRE Policy.enact(...) sample functionality which
    #  uses TACoApplication - should we change this (in `nucypher`)?
    mock_agent = mock_contract_agency.get_agent(TACoApplicationAgent)
    mock_agent.get_staking_provider_reservoir = mock_reservoir


@pytest.fixture(scope="module", autouse=True)
def mock_payment_method(module_mocker):
    module_mocker.patch.object(SubscriptionManagerPayment, "verify", return_value=True)
