
from bytestring_splitter import BytestringSplittingError
from cryptography.exceptions import InternalError


class SpecificationError(ValueError):
    """The protocol request is completely unusable"""


class InvalidInputData(SpecificationError):
    """Input data does not match the input specification"""


class InvalidArgumentCombo(SpecificationError):
    """Arguments specified are incompatible"""


InvalidNativeDataTypes = (ValueError, TypeError, BytestringSplittingError, InternalError)
