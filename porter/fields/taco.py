from nucypher_core import (
    EncryptedThresholdDecryptionRequest,
    EncryptedThresholdDecryptionResponse,
    EncryptedThresholdSignatureRequest,
    EncryptedThresholdSignatureResponse,
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
                f"Could not convert input for {self.name} to an "
                f"{EncryptedThresholdDecryptionRequest.__name__}: {e}"
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
                f"Could not convert input for {self.name} to an "
                f"{EncryptedThresholdDecryptionResponse.__name__}: {e}"
            ) from e


class EncryptedThresholdSignatureRequestField(Base64BytesRepresentation):
    """
    Parameter representation of threshold signature request.
    """

    def _serialize(self, value, attr, obj, **kwargs):
        if not isinstance(value, EncryptedThresholdSignatureRequest):
            raise InvalidInputData(
                f"Provided object is not an {EncryptedThresholdSignatureRequest.__name__}"
            )

        return super()._serialize(value, attr, obj, **kwargs)

    def _deserialize(
        self, value, attr, data, **kwargs
    ) -> EncryptedThresholdSignatureRequest:
        try:
            encrypted_threshold_signature_request_bytes = super()._deserialize(
                value, attr, data, **kwargs
            )
            return EncryptedThresholdSignatureRequest.from_bytes(
                encrypted_threshold_signature_request_bytes
            )
        except Exception as e:
            raise InvalidInputData(
                f"Could not convert input for {self.name} to an "
                f"{EncryptedThresholdSignatureRequest.__name__}: {e}"
            ) from e


class EncryptedThresholdSignatureResponseField(Base64BytesRepresentation):
    """
    Parameter representation of threshold signature response.
    """

    def _serialize(self, value, attr, obj, **kwargs):
        if not isinstance(value, EncryptedThresholdSignatureResponse):
            raise InvalidInputData(
                f"Provided object is not an {EncryptedThresholdSignatureResponse.__name__}"
            )

        return super()._serialize(value, attr, obj, **kwargs)

    def _deserialize(
        self, value, attr, data, **kwargs
    ) -> EncryptedThresholdSignatureResponse:
        try:
            encrypted_decryption_response_bytes = super()._deserialize(
                value, attr, data, **kwargs
            )
            return EncryptedThresholdSignatureResponse.from_bytes(
                encrypted_decryption_response_bytes
            )
        except Exception as e:
            raise InvalidInputData(
                f"Could not convert input for {self.name} to an "
                f"{EncryptedThresholdSignatureResponse.__name__}: {e}"
            ) from e
