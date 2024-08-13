from nucypher.policy.conditions.context import USER_ADDRESS_CONTEXT

from porter.utils import retrieval_request_setup


def test_retrieve_cfrags(porter, bob, alice, enacted_policy):
    # Setup
    retrieval_args, _ = retrieval_request_setup(enacted_policy, bob, alice)

    result = porter.retrieve_cfrags(**retrieval_args)

    assert result, "valid result returned"


def test_retrieve_cfrags_with_context(
    porter, bob, alice, enacted_policy, valid_eip4361_auth_message
):
    # Setup
    context = {USER_ADDRESS_CONTEXT: valid_eip4361_auth_message}
    retrieval_args, _ = retrieval_request_setup(
        enacted_policy, bob, alice, context=context
    )

    result = porter.retrieve_cfrags(**retrieval_args)
    assert result, "valid result returned"
