from typing import Union

from nucypher_core import (
    EncryptedThresholdDecryptionRequest as EncryptedThresholdDecryptionRequestClass,
)
from nucypher_core import (
    EncryptedThresholdDecryptionResponse as EncryptedThresholdDecryptionResponseClass,
)
from nucypher_core import (
    PackedUserOperationSignatureRequest as PackedUserOperationSignatureRequestClass,
)
from nucypher_core import (
    SignatureResponse as SignatureResponseClass,
)
from nucypher_core import (
    UserOperationSignatureRequest as UserOperationSignatureRequestClass,
)
from nucypher_core import (
    deserialize_signature_request,
)

from porter.fields.base import Base64BytesRepresentation
from porter.fields.exceptions import InvalidInputData


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

    def _deserialize(
        self, value, attr, data, **kwargs
    ) -> EncryptedThresholdDecryptionRequestClass:
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

    def _deserialize(
        self, value, attr, data, **kwargs
    ) -> EncryptedThresholdDecryptionResponseClass:
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


class SignatureRequestField(Base64BytesRepresentation):
    """
    Parameter representation of threshold signature request.
    """

    def _serialize(self, value, attr, obj, **kwargs):
        if not isinstance(
            value, PackedUserOperationSignatureRequestClass
        ) and not isinstance(value, UserOperationSignatureRequestClass):
            raise InvalidInputData("Provided object is not a valid signature request")

        return super()._serialize(value, attr, obj, **kwargs)

    def _deserialize(
        self, value, attr, data, **kwargs
    ) -> Union[
        PackedUserOperationSignatureRequestClass, UserOperationSignatureRequestClass
    ]:
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
        if not isinstance(value, SignatureResponseClass):
            raise InvalidInputData(
                f"Provided object is not an {SignatureResponseClass.__name__}"
            )

        return super()._serialize(value, attr, obj, **kwargs)

    def _deserialize(self, value, attr, data, **kwargs) -> SignatureResponseClass:
        try:
            encrypted_decryption_response_bytes = super()._deserialize(
                value, attr, data, **kwargs
            )
            return SignatureResponseClass.from_bytes(
                encrypted_decryption_response_bytes
            )
        except Exception as e:
            raise InvalidInputData(
                f"Could not convert input for {self.name} to an {SignatureResponseClass.__name__}: {e}"
            ) from e
