"""
This code portion was inspired by https://github.com/reaperhulk/vault-signing
Original license BSD-3-Clause (author: @reaperhulk)
"""
import typing

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    utils as asym_utils,
)
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509 import Certificate

from pyksef.p11 import PKCS11Lib
from pyksef.p11._alg_mapping import map_p11_mechanism


class P11RSAPrivateKey(rsa.RSAPrivateKey):
    p11_lib: PKCS11Lib
    x509_cert: Certificate

    def __init__(self, p11_lib: PKCS11Lib, x509_cert: Certificate):
        super().__init__()

        self.p11_lib = p11_lib
        self.x509_cert = x509_cert

        if not self.p11_lib.is_configured():
            raise RuntimeError("The passed p11_lib is not configured. "
                               "Use p11_lib.set_token() and p11_lib.set_private_key() first.")

    def sign(self, data: bytes, padding: AsymmetricPadding, algorithm: typing.Union[asym_utils.Prehashed, hashes.HashAlgorithm]) -> bytes:
        if not isinstance(padding, PKCS1v15):
            raise RuntimeError("Unsupported padding type requested.")

        mechanism = map_p11_mechanism(self.x509_cert)
        return self.p11_lib.sign(data=data, mechanism=mechanism, encode_sig=False)

    def public_key(self) -> RSAPublicKey:
        return self.x509_cert.public_key()

    @property
    def hash_algorithm(self):
        return self.x509_cert.signature_hash_algorithm

    @property
    def key_size(self) -> int:
        return self.x509_cert.public_key().key_size

    def __copy__(self) -> RSAPrivateKey:
        raise NotImplementedError("Object copying is not supported in this implementation.")

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError("Only asymmetric signing is supported in this implementation.")

    def private_numbers(self) -> rsa.RSAPrivateNumbers:
        raise NotImplementedError("Attempted to retrieve private key material (implementation bug?).")

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError("Attempted to retrieve private key material (implementation bug?).")
