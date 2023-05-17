from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence

from constant_sorrow.constants import NO_CONTROL_PROTOCOL
from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address
from flask import Response, request
from nucypher.blockchain.eth.agents import ContractAgency, PREApplicationAgent
from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory
from nucypher.blockchain.eth.registry import (
    BaseContractRegistry,
    InMemoryContractRegistry,
)
from nucypher.characters.lawful import Ursula
from nucypher.crypto.powers import DecryptingPower
from nucypher.network.decryption import ThresholdDecryptionClient
from nucypher.network.nodes import Learner
from nucypher.network.retrieval import PRERetrievalClient
from nucypher.policy.reservoir import PrefetchStrategy, make_staking_provider_reservoir
from nucypher.utilities.concurrency import WorkerPool
from nucypher.utilities.logging import Logger
from nucypher_core import (
    EncryptedThresholdDecryptionRequest,
    EncryptedThresholdDecryptionResponse,
    RetrievalKit,
    TreasureMap,
)
from nucypher_core.umbral import PublicKey

from porter.controllers import PorterCLIController, WebController
from porter.interfaces import PorterInterface

BANNER = r"""

 ______
(_____ \           _
 _____) )__   ____| |_  ____  ____
|  ____/ _ \ / ___)  _)/ _  )/ ___)
| |   | |_| | |   | |_( (/ /| |
|_|    \___/|_|    \___)____)_|

the Pipe for PRE Application network operations
"""


class Porter(Learner):

    APP_NAME = "Porter"

    _SHORT_LEARNING_DELAY = 2
    _LONG_LEARNING_DELAY = 30
    _ROUNDS_WITHOUT_NODES_AFTER_WHICH_TO_SLOW_DOWN = 25

    DEFAULT_EXECUTION_TIMEOUT = 15  # 15s

    DEFAULT_PORT = 9155

    _interface_class = PorterInterface

    class UrsulaInfo(NamedTuple):
        """Simple object that stores relevant Ursula information resulting from sampling."""
        checksum_address: ChecksumAddress
        uri: str
        encrypting_key: PublicKey

    class PRERetrievalOutcome(NamedTuple):
        """
        Simple object that stores the results and errors of re-encryption operations across
        one or more Ursulas.
        """

        cfrags: Dict
        errors: Dict

    class CBDDecryptionOutcome(NamedTuple):
        """
        Simple object that stores the results and errors of CBD decryption operations across
        one or more Ursulas.
        """

        encrypted_decryption_responses: Dict[
            ChecksumAddress, EncryptedThresholdDecryptionResponse
        ]
        errors: Dict[ChecksumAddress, str]

    def __init__(self,
                 domain: str = None,
                 registry: BaseContractRegistry = None,
                 controller: bool = True,
                 node_class: object = Ursula,
                 eth_provider_uri: str = None,
                 execution_timeout: int = DEFAULT_EXECUTION_TIMEOUT,
                 *args, **kwargs):
        if not eth_provider_uri:
            raise ValueError('ETH Provider URI is required for decentralized Porter.')

        if not BlockchainInterfaceFactory.is_interface_initialized(eth_provider_uri=eth_provider_uri):
            BlockchainInterfaceFactory.initialize_interface(eth_provider_uri=eth_provider_uri)

        self.registry = registry or InMemoryContractRegistry.from_latest_publication(network=domain)
        self.application_agent = ContractAgency.get_agent(PREApplicationAgent, registry=self.registry)

        super().__init__(save_metadata=True, domain=domain, node_class=node_class, *args, **kwargs)

        self.log = Logger(self.__class__.__name__)
        self.execution_timeout = execution_timeout

        # Controller Interface
        self.interface = self._interface_class(porter=self)
        self.controller = NO_CONTROL_PROTOCOL
        if controller:
            # TODO need to understand this better - only made it analogous to what was done for characters
            self.make_cli_controller()

        self.log.info(BANNER)

    def get_ursulas(self,
                    quantity: int,
                    exclude_ursulas: Optional[Sequence[ChecksumAddress]] = None,
                    include_ursulas: Optional[Sequence[ChecksumAddress]] = None) -> List[UrsulaInfo]:
        reservoir = self._make_reservoir(exclude_ursulas, include_ursulas)
        value_factory = PrefetchStrategy(reservoir, quantity)

        def get_ursula_info(ursula_address) -> Porter.UrsulaInfo:
            if to_checksum_address(ursula_address) not in self.known_nodes:
                raise ValueError(f"{ursula_address} is not known")

            ursula_address = to_checksum_address(ursula_address)
            ursula = self.known_nodes[ursula_address]
            try:
                # ensure node is up and reachable
                self.network_middleware.ping(ursula)
                return Porter.UrsulaInfo(checksum_address=ursula_address,
                                         uri=f"{ursula.rest_interface.formal_uri}",
                                         encrypting_key=ursula.public_keys(DecryptingPower))
            except Exception as e:
                self.log.debug(f"Ursula ({ursula_address}) is unreachable: {str(e)}")
                raise

        self.block_until_number_of_known_nodes_is(quantity,
                                                  timeout=self.execution_timeout,
                                                  learn_on_this_thread=True,
                                                  eager=True)

        worker_pool = WorkerPool(worker=get_ursula_info,
                                 value_factory=value_factory,
                                 target_successes=quantity,
                                 timeout=self.execution_timeout,
                                 stagger_timeout=1)
        worker_pool.start()
        try:
            successes = worker_pool.block_until_target_successes()
        finally:
            worker_pool.cancel()
            # don't wait for it to stop by "joining" - too slow...

        ursulas_info = successes.values()
        return list(ursulas_info)

    def retrieve_cfrags(
        self,
        treasure_map: TreasureMap,
        retrieval_kits: Sequence[RetrievalKit],
        alice_verifying_key: PublicKey,
        bob_encrypting_key: PublicKey,
        bob_verifying_key: PublicKey,
        context: Optional[Dict] = None,
    ) -> List[PRERetrievalOutcome]:
        client = PRERetrievalClient(self)
        context = context or dict()  # must not be None
        results, errors = client.retrieve_cfrags(
            treasure_map,
            retrieval_kits,
            alice_verifying_key,
            bob_encrypting_key,
            bob_verifying_key,
            **context,
        )
        result_outcomes = []
        for result, error in zip(results, errors):
            result_outcome = Porter.PRERetrievalOutcome(
                cfrags=result.cfrags, errors=error.errors
            )
            result_outcomes.append(result_outcome)
        return result_outcomes

    def cbd_decrypt(
        self,
        threshold: int,
        encrypted_decryption_requests: Dict[
            ChecksumAddress, EncryptedThresholdDecryptionRequest
        ],
    ) -> CBDDecryptionOutcome:
        decryption_client = ThresholdDecryptionClient(self)
        successes, failures = decryption_client.gather_encrypted_decryption_shares(
            encrypted_requests=encrypted_decryption_requests, threshold=threshold
        )

        cbd_outcome = Porter.CBDDecryptionOutcome(
            encrypted_decryption_responses=successes, errors=failures
        )
        return cbd_outcome


    def _make_reservoir(
        self,
        exclude_ursulas: Optional[Sequence[ChecksumAddress]] = None,
        include_ursulas: Optional[Sequence[ChecksumAddress]] = None,
    ):
        return make_staking_provider_reservoir(
            application_agent=self.application_agent,
            exclude_addresses=exclude_ursulas,
            include_addresses=include_ursulas,
        )

    def make_cli_controller(self, crash_on_error: bool = False):
        controller = PorterCLIController(app_name=self.APP_NAME,
                                         crash_on_error=crash_on_error,
                                         interface=self.interface)
        self.controller = controller
        return controller

    def make_web_controller(self,
                            crash_on_error: bool = False,
                            htpasswd_filepath: Path = None,
                            cors_allow_origins_list: List[str] = None):
        controller = WebController(app_name=self.APP_NAME,
                                   crash_on_error=crash_on_error,
                                   interface=self._interface_class(porter=self))
        self.controller = controller

        # Register Flask Decorator
        porter_flask_control = controller.make_control_transport()

        # CORS origins
        if cors_allow_origins_list:
            try:
                from flask_cors import CORS
            except ImportError:
                raise ImportError('Porter installation is required for to specify CORS origins '
                                  '- run "pip install nucypher[porter]" and try again.')
            _ = CORS(app=porter_flask_control, origins=cors_allow_origins_list)

        # Basic Auth
        if htpasswd_filepath:
            try:
                from flask_htpasswd import HtPasswdAuth
            except ImportError:
                raise ImportError('Porter installation is required for basic authentication '
                                  '- run "pip install nucypher[porter]" and try again.')

            porter_flask_control.config['FLASK_HTPASSWD_PATH'] = str(htpasswd_filepath.absolute())
            # ensure basic auth required for all endpoints
            porter_flask_control.config['FLASK_AUTH_ALL'] = True
            _ = HtPasswdAuth(app=porter_flask_control)

        #
        # Porter Control HTTP Endpoints
        #
        @porter_flask_control.route('/get_ursulas', methods=['GET'])
        def get_ursulas() -> Response:
            """Porter control endpoint for sampling Ursulas on behalf of Alice."""
            response = controller(method_name='get_ursulas', control_request=request)
            return response

        @porter_flask_control.route("/revoke", methods=['POST'])
        def revoke():
            """Porter control endpoint for off-chain revocation of a policy on behalf of Alice."""
            response = controller(method_name='revoke', control_request=request)
            return response

        @porter_flask_control.route("/retrieve_cfrags", methods=['POST'])
        def retrieve_cfrags() -> Response:
            """Porter control endpoint for executing a PRE work order on behalf of Bob."""
            response = controller(method_name='retrieve_cfrags', control_request=request)
            return response

        @porter_flask_control.route("/cbd_decrypt", methods=["POST"])
        def cbd_decrypt() -> Response:
            """Porter control endpoint for executing a CBD decryption request."""
            response = controller(method_name="cbd_decrypt", control_request=request)
            return response

        return controller
