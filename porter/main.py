import os
from collections import defaultdict
from json import JSONDecodeError
from pathlib import Path
from random import Random
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple, Union

import requests
from constant_sorrow.constants import NO_CONTROL_PROTOCOL
from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address
from flask import Response, request
from nucypher.blockchain.eth.agents import (
    ContractAgency,
    TACoChildApplicationAgent,
)
from nucypher.blockchain.eth.domains import DEFAULT_DOMAIN, MAINNET, TACoDomain
from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory
from nucypher.blockchain.eth.registry import ContractRegistry
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
from prometheus_flask_exporter import PrometheusMetrics

import porter
from porter.controllers import PorterCLIController, WebController
from porter.interfaces import PorterInterface

BANNER = r"""

 ______
(_____ \           _
 _____) )__   ____| |_  ____  ____
|  ____/ _ \ / ___)  _)/ _  )/ ___)
| |   | |_| | |   | |_( (/ /| |
|_|    \___/|_|    \___)____)_|

the Pipe for TACo Application operations
"""


class Porter(Learner):

    APP_NAME = "Porter"

    _SHORT_LEARNING_DELAY = 2
    _LONG_LEARNING_DELAY = 30
    _ROUNDS_WITHOUT_NODES_AFTER_WHICH_TO_SLOW_DOWN = 25

    _ALLOWED_DOMAINS_FOR_BUCKET_SAMPLING = (MAINNET,)

    DEFAULT_PORT = 9155

    MAX_GET_URSULAS_TIMEOUT = os.getenv("PORTER_MAX_GET_URSULAS_TIMEOUT", default=15)
    MAX_BUCKET_SAMPLING_TIMEOUT = os.getenv(
        "PORTER_MAX_BUCKET_SAMPLING_TIMEOUT", default=25
    )
    MAX_DECRYPTION_TIMEOUT = os.getenv(
        "PORTER_MAX_DECRYPTION_TIMEOUT",
        default=ThresholdDecryptionClient.DEFAULT_DECRYPTION_TIMEOUT,
    )

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

    class DecryptOutcome(NamedTuple):
        """
        Simple object that stores the results and errors of TACo decrypt operations across
        one or more Ursulas.
        """

        encrypted_decryption_responses: Dict[
            ChecksumAddress, EncryptedThresholdDecryptionResponse
        ]
        errors: Dict[ChecksumAddress, str]

    def __init__(
        self,
        eth_endpoint: str,
        polygon_endpoint: str,
        domain: TACoDomain = DEFAULT_DOMAIN,
        registry: ContractRegistry = None,
        controller: bool = True,
        node_class: object = Ursula,
        *args,
        **kwargs,
    ):
        if not domain:
            raise ValueError("TACo Domain must be provided.")
        if not eth_endpoint:
            raise ValueError("ETH Provider URI must be provided.")
        if not polygon_endpoint:
            raise ValueError("Polygon Provider URI must be provided.")

        self._initialize_endpoints(eth_endpoint, polygon_endpoint)
        self.eth_endpoint, self.polygon_endpoint = eth_endpoint, polygon_endpoint

        self.registry = registry or ContractRegistry.from_latest_publication(
            domain=domain
        )
        self.taco_child_application_agent = ContractAgency.get_agent(
            TACoChildApplicationAgent,
            registry=self.registry,
            blockchain_endpoint=self.polygon_endpoint,
        )

        super().__init__(save_metadata=True, domain=domain, node_class=node_class, *args, **kwargs)

        self.log = Logger(self.__class__.__name__)

        # Controller Interface
        self.interface = self._interface_class(porter=self)
        self.controller = NO_CONTROL_PROTOCOL
        if controller:
            # TODO need to understand this better - only made it analogous to what was done for characters
            self.make_cli_controller()

        self.log.info(BANNER)

    @staticmethod
    def _initialize_endpoints(eth_endpoint: str, polygon_endpoint: str):
        if not BlockchainInterfaceFactory.is_interface_initialized(
            endpoint=eth_endpoint
        ):
            BlockchainInterfaceFactory.initialize_interface(endpoint=eth_endpoint)

        if not BlockchainInterfaceFactory.is_interface_initialized(
            endpoint=polygon_endpoint
        ):
            BlockchainInterfaceFactory.initialize_interface(endpoint=polygon_endpoint)

    @staticmethod
    def _parse_version(version: Optional[str] = None) -> list:
        if not version:
            return [0, 0, 0]
        parsed = version.split("\.")
        if len(parsed) <= 1:
            raise InvalidInputData("Minimum version must have x.x.x format")
        return parsed
    
    @staticmethod
    def _is_version_greater_or_equal(min_version: list, version: list) -> bool:
        for i in version:
            if (version[i] < min_version[i]):
                return False
        return True
    
    def _get_ursula_version(self, ursula: Ursula) -> list:
        response = self.network_middleware.client.get(node_or_sprout=ursula, path="status/?json=true")
        return self._parse_version(response["version"])

    def get_ursulas(
        self,
        quantity: int,
        exclude_ursulas: Optional[Sequence[ChecksumAddress]] = None,
        include_ursulas: Optional[Sequence[ChecksumAddress]] = None,
        timeout: Optional[int] = None,
        duration: Optional[int] = None,
        min_version: Optional[str] = None,
    ) -> List[UrsulaInfo]:
        timeout = self._configure_timeout(
            "sampling", timeout, self.MAX_GET_URSULAS_TIMEOUT
        )
        duration = duration or 0
        min_version_parsed = self._parse_version(min_version)

        reservoir = self._make_reservoir(exclude_ursulas, include_ursulas, duration)
        available_nodes_to_sample = len(reservoir.values) + len(reservoir.reservoir)
        if available_nodes_to_sample < quantity:
            raise ValueError(
                f"Insufficient nodes ({available_nodes_to_sample}) from which to sample {quantity}"
            )

        value_factory = PrefetchStrategy(reservoir, quantity)

        def get_ursula_info(ursula_address) -> Porter.UrsulaInfo:
            if to_checksum_address(ursula_address) not in self.known_nodes:
                raise ValueError(f"{ursula_address} is not known")

            ursula_address = to_checksum_address(ursula_address)
            ursula = self.known_nodes[ursula_address]
            try:
                # ensure node is up and reachable
                # self.network_middleware.ping(ursula)
                version = self._get_ursula_version(ursula)
                if not self._is_version_greater_or_equal(min_version_parsed, version):
                    raise ValueError(f"Ursula ({ursula_address}) has too old version ({version})")
                
                return Porter.UrsulaInfo(checksum_address=ursula_address,
                                         uri=f"{ursula.rest_interface.formal_uri}",
                                         encrypting_key=ursula.public_keys(DecryptingPower))
            except Exception as e:
                self.log.debug(f"Ursula ({ursula_address}) is unreachable: {str(e)}")
                raise

        self.block_until_number_of_known_nodes_is(
            quantity, timeout=timeout, learn_on_this_thread=True, eager=True
        )

        worker_pool = WorkerPool(
            worker=get_ursula_info,
            value_factory=value_factory,
            target_successes=quantity,
            timeout=timeout,
            stagger_timeout=1,
        )
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
            context,
        )
        result_outcomes = []
        for result, error in zip(results, errors):
            result_outcome = Porter.PRERetrievalOutcome(
                cfrags=result.cfrags, errors=error.errors
            )
            result_outcomes.append(result_outcome)
        return result_outcomes

    def decrypt(
        self,
        threshold: int,
        encrypted_decryption_requests: Dict[
            ChecksumAddress, EncryptedThresholdDecryptionRequest
        ],
        timeout: Optional[int] = None,
    ) -> DecryptOutcome:
        decryption_client = ThresholdDecryptionClient(self)
        timeout = self._configure_timeout(
            "decryption", timeout, self.MAX_DECRYPTION_TIMEOUT
        )

        successes, failures = decryption_client.gather_encrypted_decryption_shares(
            encrypted_requests=encrypted_decryption_requests,
            threshold=threshold,
            timeout=timeout,
        )

        decrypt_outcome = Porter.DecryptOutcome(
            encrypted_decryption_responses=successes, errors=failures
        )
        return decrypt_outcome

    def _configure_timeout(
        self, operation: str, timeout: Union[int, None], max_timeout: int
    ):
        if timeout and timeout > max_timeout:
            self.log.warn(
                f"Provided {operation} timeout ({timeout}s) exceeds "
                f"maximum ({max_timeout}s); "
                f"using {max_timeout}s instead"
            )
            timeout = max_timeout
        else:
            timeout = timeout or max_timeout
        return timeout

    def _make_reservoir(
        self,
        exclude_ursulas: Optional[Sequence[ChecksumAddress]] = None,
        include_ursulas: Optional[Sequence[ChecksumAddress]] = None,
        duration: Optional[int] = 0,
    ):
        return make_staking_provider_reservoir(
            application_agent=self.taco_child_application_agent,
            exclude_addresses=exclude_ursulas,
            include_addresses=include_ursulas,
            duration=duration,
        )

    def bucket_sampling(
        self,
        quantity: int,
        random_seed: Optional[int] = None,
        exclude_ursulas: Optional[Sequence[ChecksumAddress]] = None,
        timeout: Optional[int] = None,
        duration: Optional[int] = None,
        min_version: Optional[str] = None,
    ) -> Tuple[List[ChecksumAddress], int]:
        timeout = self._configure_timeout(
            "bucket_sampling", timeout, self.MAX_BUCKET_SAMPLING_TIMEOUT
        )
        duration = duration or 0
        min_version_parsed = self._parse_version(min_version)

        if self.domain not in self._ALLOWED_DOMAINS_FOR_BUCKET_SAMPLING:
            raise ValueError("Bucket sampling is only for TACo Mainnet")

        class RandomizedStakingProvidersReservoir:
            def __init__(
                self,
                staking_providers: Sequence[ChecksumAddress],
                seed: Optional[int] = None,
            ):
                self._providers = list(staking_providers)
                rng = Random(seed)
                rng.shuffle(self._providers)

            def __len__(self):
                return len(self._providers)

            def draw(self, _quantity):
                if _quantity > len(self._providers):
                    raise ValueError(
                        f"Cannot sample {_quantity} out of {len(self._providers)} total staking providers"
                    )
                sampled, self._providers = (
                    self._providers[:_quantity],
                    self._providers[_quantity:],
                )
                return sampled

            def __call__(self) -> Optional[ChecksumAddress]:
                if len(self._providers) > 0:
                    return self.draw(1)[0]
                else:
                    return None

        block_number = self.taco_child_application_agent.blockchain.client.block_number
        _, sp_map = self.taco_child_application_agent.get_all_active_staking_providers(
            duration=duration
        )
        for e in exclude_ursulas or []:
            if e in sp_map:
                del sp_map[e]

        if len(sp_map) < quantity:
            raise ValueError(
                f"Insufficient nodes ({len(sp_map)}) from which to sample {quantity}"
            )

        reservoir = RandomizedStakingProvidersReservoir(list(sp_map), random_seed)

        class BucketPrefetchStrategy:
            BUCKET_CAP = 2
            BUCKETS_URL = (
                "https://raw.githubusercontent.com/"
                "threshold-network/trust/main/taco-self-disclosed-buckets.json"
            )

            def __init__(self, _reservoir, need_successes: int):
                self.reservoir = _reservoir
                self.need_successes = need_successes
                self.predefined_buckets = self.read_buckets()
                self.bucketed_nodes = defaultdict(list)

            def read_buckets(self) -> Dict:
                try:
                    response = requests.get(self.BUCKETS_URL)
                except requests.exceptions.ConnectionError as ex:
                    error = f"Failed to fetch buckets JSON file from {self.BUCKETS_URL}: {str(ex)}"
                    raise RuntimeError(error)

                if response.status_code != 200:
                    error = f"Failed to fetch buckets JSON file from {self.BUCKETS_URL} with status code {response.status_code}"
                    raise RuntimeError(error)

                try:
                    buckets = response.json()
                except JSONDecodeError:
                    raise RuntimeError(
                        f"Invalid buckets JSON file at '{self.BUCKETS_URL}'."
                    )
                return buckets

            def find_bucket(self, node):
                for bucket_name, bucket in self.predefined_buckets.items():
                    if node in bucket:
                        return bucket_name
                return None

            def __call__(self, _successes: int) -> Optional[List[ChecksumAddress]]:
                batch = []
                batch_size = self.need_successes - _successes
                while len(batch) < batch_size:
                    selected = self.reservoir()
                    if selected is None:
                        break
                    bucket = self.find_bucket(selected)
                    if bucket:
                        if len(self.bucketed_nodes[bucket]) >= self.BUCKET_CAP:
                            continue
                        self.bucketed_nodes[bucket].append(selected)
                    batch.append(selected)
                if not batch:
                    return None
                return batch

        value_factory = BucketPrefetchStrategy(reservoir, quantity)

        def make_sure_ursula_is_online(ursula_address) -> ChecksumAddress:
            if to_checksum_address(ursula_address) not in self.known_nodes:
                raise ValueError(f"{ursula_address} is not known")

            ursula_address = to_checksum_address(ursula_address)
            ursula = self.known_nodes[ursula_address]
            try:
                # ensure node is up and reachable
                # self.network_middleware.ping(ursula)
                version = self._get_ursula_version(ursula)
                if not self._is_version_greater_or_equal(min_version_parsed, version):
                    raise ValueError(f"Ursula ({ursula_address}) has too old version ({version})")
                
                return ursula_address
            except Exception as e:
                message = f"Ursula ({ursula_address}) is unreachable: {str(e)}"
                self.log.debug(message)
                raise

        self.block_until_number_of_known_nodes_is(
            quantity, timeout=timeout, learn_on_this_thread=True, eager=True
        )

        worker_pool = WorkerPool(
            worker=make_sure_ursula_is_online,
            value_factory=value_factory,
            target_successes=quantity,
            timeout=timeout,
            stagger_timeout=4,  # default connection timeout for middleware calls (incl. pings) is 3s
        )
        worker_pool.start()
        try:
            successes = worker_pool.block_until_target_successes()
        finally:
            worker_pool.cancel()
            # don't wait for it to stop by "joining" - too slow...

        provider_addresses = list(sorted(successes.values(), key=lambda x: x.lower()))
        return provider_addresses, block_number

    def make_cli_controller(self, crash_on_error: bool = False):
        controller = PorterCLIController(app_name=self.APP_NAME,
                                         crash_on_error=crash_on_error,
                                         interface=self.interface)
        self.controller = controller
        return controller

    def _setup_prometheus(self, app):
        self.controller.metrics = PrometheusMetrics(app)

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
        self._setup_prometheus(porter_flask_control)

        # static information as metric
        self.controller.metrics.info(
            "app_info", "Porter Application info", version=porter.__version__
        )
        by_path_counter = controller.metrics.counter(
            "by_path_counter",
            "Request count by request paths",
            labels={"path": lambda: request.path},
        )

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
        @porter_flask_control.route("/get_ursulas", methods=["GET"])
        @by_path_counter
        def get_ursulas() -> Response:
            """Porter control endpoint for sampling Ursulas on behalf of Alice."""
            response = controller(method_name="get_ursulas", control_request=request)
            return response

        @porter_flask_control.route("/revoke", methods=["POST"])
        @by_path_counter
        def revoke():
            """Porter control endpoint for off-chain revocation of a policy on behalf of Alice."""
            response = controller(method_name="revoke", control_request=request)
            return response

        @porter_flask_control.route("/retrieve_cfrags", methods=["POST"])
        @by_path_counter
        def retrieve_cfrags() -> Response:
            """Porter control endpoint for executing a PRE work order on behalf of Bob."""
            response = controller(
                method_name="retrieve_cfrags", control_request=request
            )
            return response

        @porter_flask_control.route("/decrypt", methods=["POST"])
        @by_path_counter
        def decrypt() -> Response:
            """Porter control endpoint for executing a TACo decryption request."""
            response = controller(method_name="decrypt", control_request=request)
            return response

        @porter_flask_control.route("/bucket_sampling", methods=["GET"])
        @by_path_counter
        def bucket_sampling() -> Response:
            """Porter control endpoint for sampling Ursulas with provider caps (a.k.a. bucket sampling)"""
            response = controller(
                method_name="bucket_sampling", control_request=request
            )
            return response

        return controller
