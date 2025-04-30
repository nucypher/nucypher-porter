from nucypher_core import (
    EncryptedThresholdDecryptionRequest as EncryptedThresholdDecryptionRequestClass,
)
from nucypher_core import (
    EncryptedThresholdDecryptionResponse as EncryptedThresholdDecryptionResponseClass,
)

from porter.fields.base import Base64BytesRepresentation
from porter.fields.exceptions import InvalidInputData

# TODO: move this to nucypher_core
from nucypher.types import ThresholdSignatureRequest as ThresholdSignatureRequestClass
from nucypher.types import ThresholdSignatureResponse as ThresholdSignatureResponseClass


class EncryptedThresholdDecryptionRequestField(Base64BytesRepresentation):
    """
    Parameter representation of encrypted threshold decryption request.
    """

    def _serialize(self, value, attr, obj, **kwargs):
        if not isinstance(value, EncryptedThresholdDecryptionRequestClass):
            raise InvalidInputData(
                f"Provided object is not an {EncryptedThresholdDecryptionRequestClass.__name__}"
            )

        return super()._serialize(value, attr, obj, **kwargs)

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
                f"Could not convert input for {self.name} to an {EncryptedThresholdDecryptionRequestClass.__name__}: {e}"
            ) from e


class EncryptedThresholdDecryptionResponseField(Base64BytesRepresentation):
    """
    Parameter representation of encrypted threshold decryption response.
    """

    def _serialize(self, value, attr, obj, **kwargs):
        if not isinstance(value, EncryptedThresholdDecryptionResponseClass):
            raise InvalidInputData(
                f"Provided object is not an {EncryptedThresholdDecryptionResponseClass.__name__}"
            )

        return super()._serialize(value, attr, obj, **kwargs)

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
                f"Could not convert input for {self.name} to an {EncryptedThresholdDecryptionResponseClass.__name__}: {e}"
            ) from e


class ThresholdSigningRequestField(Base64BytesRepresentation):
    """
    Parameter representation of threshold signing request.
    """

    def _serialize(self, value, attr, obj, **kwargs):
        if not isinstance(value, ThresholdSignatureRequestClass):
            raise InvalidInputData(
                f"Provided object is not an {ThresholdSignatureRequestClass.__name__}"
            )

        return super()._serialize(value, attr, obj, **kwargs)

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            threshold_signing_request_bytes = super()._deserialize(
                value, attr, data, **kwargs
            )
            return ThresholdSignatureRequestClass.from_bytes(
                threshold_signing_request_bytes
            )
        except Exception as e:
            raise InvalidInputData(
                f"Could not convert input for {self.name} to an {ThresholdSignatureRequestClass.__name__}: {e}"
            ) from e


class ThresholdSignatureResponseField(Base64BytesRepresentation):
    """
    Parameter representation of threshold signature response.
    """

    def _serialize(self, value, attr, obj, **kwargs):
        if not isinstance(value, ThresholdSignatureResponseClass):
            raise InvalidInputData(
                f"Provided object is not an {ThresholdSignatureResponseClass.__name__}"
            )

        return super()._serialize(value, attr, obj, **kwargs)

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            encrypted_decryption_response_bytes = super()._deserialize(
                value, attr, data, **kwargs
            )
            return ThresholdSignatureResponseClass.from_bytes(
                encrypted_decryption_response_bytes
            )
        except Exception as e:
            raise InvalidInputData(
                f"Could not convert input for {self.name} to an {ThresholdSignatureResponseClass.__name__}: {e}"
            ) from e
