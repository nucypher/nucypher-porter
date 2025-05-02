import functools
from typing import Dict, List, Optional

from eth_typing import ChecksumAddress
from nucypher.types import ThresholdSignatureRequest
from nucypher_core import EncryptedThresholdDecryptionRequest, RetrievalKit, TreasureMap
from nucypher_core.umbral import PublicKey

from porter import main, schema


def attach_schema(schema):
    def callable(func):
        func._schema = schema()

        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            return func(*args, **kwargs)

        return wrapped

    return callable


class ControlInterface:

    def __init__(self, implementer=None, *args, **kwargs):
        self.implementer = implementer
        super().__init__(*args, **kwargs)


class PorterInterface(ControlInterface):
    def __init__(self, porter: "main.Porter" = None, *args, **kwargs):
        super().__init__(implementer=porter, *args, **kwargs)

    @attach_schema(schema.GetUrsulas)
    def get_ursulas(
        self,
        quantity: int,
        exclude_ursulas: Optional[List[ChecksumAddress]] = None,
        include_ursulas: Optional[List[ChecksumAddress]] = None,
        timeout: Optional[int] = None,
        duration: Optional[int] = None,
        min_version: Optional[str] = None,
    ) -> Dict:
        ursulas_info = self.implementer.get_ursulas(
            quantity=quantity,
            exclude_ursulas=exclude_ursulas,
            include_ursulas=include_ursulas,
            timeout=timeout,
            duration=duration,
            min_version=min_version,
        )

        response_data = {"ursulas": ursulas_info}  # list of UrsulaInfo objects
        return response_data

    @attach_schema(schema.PRERevoke)
    def revoke(self) -> dict:
        # Steps (analogous to nucypher.character.control.interfaces):
        # 1. creation of objects / setup
        # 2. call self.implementer.some_function() i.e. Porter learner has an associated function to call
        # 3. create response
        pass

    @attach_schema(schema.PRERetrieveCFrags)
    def retrieve_cfrags(self,
                        treasure_map: TreasureMap,
                        retrieval_kits: List[RetrievalKit],
                        alice_verifying_key: PublicKey,
                        bob_encrypting_key: PublicKey,
                        bob_verifying_key: PublicKey,
                        context: Optional[Dict] = None) -> Dict:
        retrieval_outcomes = self.implementer.retrieve_cfrags(
            treasure_map=treasure_map,
            retrieval_kits=retrieval_kits,
            alice_verifying_key=alice_verifying_key,
            bob_encrypting_key=bob_encrypting_key,
            bob_verifying_key=bob_verifying_key,
            context=context,
        )
        response_data = {
            "retrieval_results": retrieval_outcomes
        }  # list of RetrievalOutcome objects
        return response_data

    @attach_schema(schema.Decrypt)
    def decrypt(
        self,
        threshold: int,
        encrypted_decryption_requests: Dict[
            ChecksumAddress, EncryptedThresholdDecryptionRequest
        ],
        timeout: Optional[int] = None,
    ):
        decrypt_outcome = self.implementer.decrypt(
            threshold=threshold,
            encrypted_decryption_requests=encrypted_decryption_requests,
            timeout=timeout,
        )
        response_data = {"decryption_results": decrypt_outcome}
        return response_data

    @attach_schema(schema.Sign)
    def sign(
        self,
        signing_requests: Dict[ChecksumAddress, ThresholdSignatureRequest],
        threshold: int,
        timeout: Optional[int] = None,
    ):
        signing_outcome = self.implementer.sign(
            signing_requests=signing_requests,
            threshold=threshold,
            timeout=timeout,
        )
        response_data = {"signing_results": signing_outcome}
        return response_data

    @attach_schema(schema.BucketSampling)
    def bucket_sampling(
        self,
        quantity: int,
        random_seed: Optional[int] = None,
        exclude_ursulas: Optional[List[ChecksumAddress]] = None,
        timeout: Optional[int] = None,
        duration: Optional[int] = None,
        min_version: Optional[str] = None,
    ) -> Dict:
        ursulas, block_number = self.implementer.bucket_sampling(
            quantity=quantity,
            random_seed=random_seed,
            exclude_ursulas=exclude_ursulas,
            timeout=timeout,
            duration=duration,
            min_version=min_version,
        )

        response_data = {"ursulas": ursulas, "block_number": block_number}
        return response_data
