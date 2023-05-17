from nucypher_core import (
    EncryptedThresholdDecryptionRequest as EncryptedThresholdDecryptionRequestClass,
)
from nucypher_core import (
    EncryptedThresholdDecryptionResponse as EncryptedThresholdDecryptionResponseClass,
)

from porter.fields.base import Base64BytesRepresentation
from porter.fields.exceptions import InvalidInputData


class EncryptedThresholdDecryptionRequest(Base64BytesRepresentation):
    """
    Parameter representation of encrypted threshold decryption request.
    """

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            encrypted_decryption_request_bytes = super()._deserialize(
                value, attr, data, **kwargs
            )
            return EncryptedThresholdDecryptionRequestClass.from_bytes(
                encrypted_decryption_request_bytes
            )
        except Exception as e:
            raise InvalidInputData(
                f"Could not convert input for {self.name} to an EncryptedThresholdDecryptionRequest: {e}"
            ) from e


class EncryptedThresholdDecryptionResponse(Base64BytesRepresentation):
    def _deserialize(self, value, attr, data, **kwargs):
        try:
            encrypted_decryption_response_bytes = super()._deserialize(
                value, attr, data, **kwargs
            )
            return EncryptedThresholdDecryptionResponseClass.from_bytes(
                encrypted_decryption_response_bytes
            )
        except Exception as e:
            raise InvalidInputData(
                f"Could not convert input for {self.name} to an EncryptedThresholdDecryptionResponse: {e}"
            ) from e
