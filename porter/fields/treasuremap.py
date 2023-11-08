from nucypher_core import TreasureMap as TreasureMapClass

from porter.fields.base import Base64BytesRepresentation
from porter.fields.exceptions import InvalidInputData


class TreasureMap(Base64BytesRepresentation):
    """
    JSON Parameter representation of (unencrypted) TreasureMap.
    """
    def _deserialize(self, value, attr, data, **kwargs):
        try:
            treasure_map_bytes = super()._deserialize(value, attr, data, **kwargs)
            return TreasureMapClass.from_bytes(treasure_map_bytes)
        except Exception as e:
            raise InvalidInputData(f"Could not convert input for {self.name} to a TreasureMap: {e}") from e
