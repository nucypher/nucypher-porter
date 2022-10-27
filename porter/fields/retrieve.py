from nucypher_core import RetrievalKit as RetrievalKitClass
from nucypher_core.umbral import CapsuleFrag as CapsuleFragClass

from porter.fields.base import Base64BytesRepresentation
from porter.fields.exceptions import InvalidInputData


class RetrievalKit(Base64BytesRepresentation):
    def _deserialize(self, value, attr, data, **kwargs):
        try:
            # decode base64 to bytes
            retrieval_kit_bytes = super()._deserialize(value, attr, data, **kwargs)
            return RetrievalKitClass.from_bytes(retrieval_kit_bytes)
        except Exception as e:
            raise InvalidInputData(f"Could not convert input for {self.name} to a valid RetrievalKit: {e}")


class CapsuleFrag(Base64BytesRepresentation):
    def _deserialize(self, value, attr, data, **kwargs):
        try:
            capsule_frag_bytes = super()._deserialize(value, attr, data, **kwargs)
            return CapsuleFragClass.from_bytes(capsule_frag_bytes)
        except Exception as e:
            raise InvalidInputData(f"Could not parse {self.name}: {e}")
