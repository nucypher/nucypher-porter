from typing import Union

from nucypher_core import (
    EncryptedThresholdDecryptionRequest,
    EncryptedThresholdDecryptionResponse,
    PackedUserOperationSignatureRequest,
    SignatureResponse,
    UserOperationSignatureRequest,
    deserialize_signature_request,
)

from porter.fields.base import Base64BytesRepresentation
from porter.fields.exceptions import InvalidInputData


class EncryptedThresholdDecryptionRequestField(Base64BytesRepresentation):
    """
    Parameter representation of encrypted threshold decryption request.
    """

    def _serialize(self, value, attr, obj, **kwargs):
        if not isinstance(value, EncryptedThresholdDecryptionRequest):
            raise InvalidInputData(
                f"Provided object is not an {EncryptedThresholdDecryptionRequest.__name__}"
            )

        return super()._serialize(value, attr, obj, **kwargs)

    def _deserialize(
        self, value, attr, data, **kwargs
    ) -> EncryptedThresholdDecryptionRequest:
        try:
            encrypted_decryption_request_bytes = super()._deserialize(
                value, attr, data, **kwargs
            )
            return EncryptedThresholdDecryptionRequest.from_bytes(
                encrypted_decryption_request_bytes
            )
        except Exception as e:
            raise InvalidInputData(
                f"Could not convert input for {self.name} to an {EncryptedThresholdDecryptionRequest.__name__}: {e}"
            ) from e


class EncryptedThresholdDecryptionResponseField(Base64BytesRepresentation):
    """
    Parameter representation of encrypted threshold decryption response.
    """

    def _serialize(self, value, attr, obj, **kwargs):
        if not isinstance(value, EncryptedThresholdDecryptionResponse):
            raise InvalidInputData(
                f"Provided object is not an {EncryptedThresholdDecryptionResponse.__name__}"
            )

        return super()._serialize(value, attr, obj, **kwargs)

    def _deserialize(
        self, value, attr, data, **kwargs
    ) -> EncryptedThresholdDecryptionResponse:
        try:
            encrypted_decryption_response_bytes = super()._deserialize(
                value, attr, data, **kwargs
            )
            return EncryptedThresholdDecryptionResponse.from_bytes(
                encrypted_decryption_response_bytes
            )
        except Exception as e:
            raise InvalidInputData(
                f"Could not convert input for {self.name} to an {EncryptedThresholdDecryptionResponse.__name__}: {e}"
            ) from e


class SignatureRequestField(Base64BytesRepresentation):
    """
    Parameter representation of threshold signature request.
    """

    def _serialize(self, value, attr, obj, **kwargs):
        if not isinstance(
            value,
            (
                PackedUserOperationSignatureRequest,
                UserOperationSignatureRequest,
            ),
        ):
            raise InvalidInputData("Provided object is not a valid signature request")

        return super()._serialize(value, attr, obj, **kwargs)

    def _deserialize(
        self, value, attr, data, **kwargs
    ) -> Union[PackedUserOperationSignatureRequest, UserOperationSignatureRequest]:
        try:
            threshold_signature_request_bytes = super()._deserialize(
                value, attr, data, **kwargs
            )
            return deserialize_signature_request(threshold_signature_request_bytes)
        except Exception as e:
            raise InvalidInputData(
                f"Could not deserialize data for {self.name} to a valid signature request: {e}"
            ) from e


class SignatureResponseField(Base64BytesRepresentation):
    """
    Parameter representation of threshold signature response.
    """

    def _serialize(self, value, attr, obj, **kwargs):
        if not isinstance(value, SignatureResponse):
            raise InvalidInputData(
                f"Provided object is not an {SignatureResponse.__name__}"
            )

        return super()._serialize(value, attr, obj, **kwargs)

    def _deserialize(self, value, attr, data, **kwargs) -> SignatureResponse:
        try:
            encrypted_decryption_response_bytes = super()._deserialize(
                value, attr, data, **kwargs
            )
            return SignatureResponse.from_bytes(encrypted_decryption_response_bytes)
        except Exception as e:
            raise InvalidInputData(
                f"Could not convert input for {self.name} to an {SignatureResponse.__name__}: {e}"
            ) from e
