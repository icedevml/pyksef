from collections import namedtuple

import pkcs11
from cryptography.x509 import load_der_x509_certificate
from pkcs11 import Mechanism, ObjectClass, Attribute, UserNotLoggedIn
from pkcs11.util.dsa import encode_dsa_signature


class PKCS11Lib:
    def __init__(self, provider_dll_path: str):
        self._lib = pkcs11.lib(provider_dll_path)
        self.token_specifier = None
        self.user_pin = None
        self.key_specifier = None

    def set_token(self, *, token_label: str | None = None, token_serial: bytes | None = None, user_pin: str):
        token_specifier = {}

        if token_label:
            token_specifier["token_label"] = token_label

        if token_serial:
            token_specifier["token_serial"] = token_serial

        if not token_specifier:
            raise ValueError("You must provide at least token_label or token_serial parameter.")

        self.token_specifier = token_specifier
        self.user_pin = user_pin

    def set_private_key(self, *, key_label: str | None = None, key_id: bytes | None = None):
        key_specifier = {}

        if key_label:
            key_specifier["label"] = key_label

        if key_id:
            key_specifier["id"] = key_id

        if not key_specifier:
            raise ValueError("You must provide at least key_label or key_id parameter.")

        self.key_specifier = key_specifier

    def get_tokens(self):
        TokenRecord = namedtuple('TokenRecord',
                                 ['slot', 'label', 'serial', 'manufacturer_id', 'model', 'hardware_version',
                                  'firmware_version', 'flags'])

        for token in self._lib.get_tokens():
            yield TokenRecord(
                slot=token.slot,
                label=token.label,
                serial=token.serial.hex(),
                manufacturer_id=token.manufacturer_id,
                model=token.model,
                hardware_version=token.hardware_version,
                firmware_version=token.firmware_version,
                flags=token.flags
            )

    def get_private_keys(self):
        PrivateKeyRecord = namedtuple('PrivateKeyRecord', ['label', 'id', 'key_type'])
        token = self._lib.get_token(**self.token_specifier)

        with token.open(user_pin=self.user_pin) as session:
            for obj in session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}):
                yield PrivateKeyRecord(label=obj.label, id=obj.id.hex(), key_type=obj.key_type)

    def get_certificates(self):
        CertificateRecord = namedtuple('CertificateRecord', ['x509_cert'])
        token = self._lib.get_token(**self.token_specifier)

        with token.open(user_pin=self.user_pin) as session:
            for obj in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
                x509_cert = load_der_x509_certificate(obj[Attribute.VALUE])
                yield CertificateRecord(x509_cert=x509_cert)

    def is_configured(self):
        return self.token_specifier and self.key_specifier

    def sign(self, data: bytes, *, mechanism: Mechanism | None = None, encode_sig: bool):
        token = self._lib.get_token(**self.token_specifier)

        session = token.open(user_pin=self.user_pin)
        try:
            key = session.get_key(ObjectClass.PRIVATE_KEY, **self.key_specifier)
            sig = key.sign(data, mechanism=mechanism)

            if encode_sig:
                return encode_dsa_signature(sig)
            else:
                return sig
        finally:
            try:
                session.close()
            except UserNotLoggedIn:
                pass  # ignore
            except Exception as e:
                raise e
