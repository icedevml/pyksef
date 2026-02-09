from dataclasses import dataclass
from enum import Enum


class ContextIdentifierType(Enum):
    nip = "Nip"
    nipVatUe = "NipVatUe"
    internalId = "InternalId"


@dataclass
class ContextIdentifier:
    type: ContextIdentifierType
    value: str

    def serialize(self):
        return f'<{self.type.value}>{self.value}</{self.type.value}>'


class SubjectIdentifierType(Enum):
    certificateSubject = "certificateSubject"
    certificateFingerprint = "certificateFingerprint"
