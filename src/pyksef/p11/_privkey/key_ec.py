"""
This code portion was inspired by https://github.com/reaperhulk/vault-signing
Original license BSD-3-Clause (author: @reaperhulk)
"""
from cryptography.x509 import Certificate

from cryptography import utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurveSignatureAlgorithm, EllipticCurve, ECDH, \
    EllipticCurvePublicKey, EllipticCurvePrivateKey, EllipticCurvePrivateNumbers

from pyksef.p11._alg_mapping import map_p11_mechanism
from pyksef.p11._lib_wrapper import PKCS11Lib


class P11ECPrivateKey(ec.EllipticCurvePrivateKey):
    p11_lib: PKCS11Lib
    x509_cert: Certificate

    def __init__(self, p11_lib: PKCS11Lib, x509_cert: Certificate):
        super().__init__()

        self.p11_lib = p11_lib
        self.x509_cert = x509_cert

        if not self.p11_lib.is_configured():
            raise RuntimeError("The passed p11_lib is not configured. "
                               "Use p11_lib.set_token() and p11_lib.set_key() first.")

    def sign(self, data: utils.Buffer, signature_algorithm: EllipticCurveSignatureAlgorithm) -> bytes:
        mechanism = map_p11_mechanism(self.x509_cert)
        return self.p11_lib.sign(data=data, mechanism=mechanism, encode_sig=True)

    def public_key(self) -> EllipticCurvePublicKey:
        return self.x509_cert.public_key()

    @property
    def hash_algorithm(self):
        return self.x509_cert.signature_hash_algorithm

    @property
    def curve(self) -> EllipticCurve:
        return self.x509_cert.public_key().curve

    @property
    def key_size(self) -> int:
        return self.x509_cert.public_key().key_size

    def __copy__(self) -> EllipticCurvePrivateKey:
        raise NotImplementedError("Object copying is not supported in this implementation.")

    def exchange(self, algorithm: ECDH, peer_public_key: EllipticCurvePublicKey) -> bytes:
        raise NotImplementedError("Key exchange is not supported in this implementation.")

    def private_numbers(self) -> EllipticCurvePrivateNumbers:
        raise NotImplementedError("Attempted to retrieve private key material (implementation bug?).")

    def private_bytes(self, encoding: serialization.Encoding, format: serialization.PrivateFormat,
                      encryption_algorithm: serialization.KeySerializationEncryption) -> bytes:
        raise NotImplementedError("Attempted to retrieve private key material (implementation bug?).")
