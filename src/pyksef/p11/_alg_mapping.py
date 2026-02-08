from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.x509 import Certificate
from pkcs11.mechanisms import Mechanism
from signxml import SignatureMethod

_MAPPING = [
    # ECDSA
    (ec.ECDSA, hashes.SHA1, Mechanism.ECDSA_SHA1, SignatureMethod.ECDSA_SHA1),
    (ec.ECDSA, hashes.SHA224, Mechanism.ECDSA_SHA224, SignatureMethod.ECDSA_SHA224),
    (ec.ECDSA, hashes.SHA256, Mechanism.ECDSA_SHA256, SignatureMethod.ECDSA_SHA256),
    (ec.ECDSA, hashes.SHA384, Mechanism.ECDSA_SHA384, SignatureMethod.ECDSA_SHA384),
    (ec.ECDSA, hashes.SHA512, Mechanism.ECDSA_SHA512, SignatureMethod.ECDSA_SHA512),

    # RSA
    (padding.PKCS1v15, hashes.SHA1, Mechanism.SHA1_RSA_PKCS, SignatureMethod.RSA_SHA1),
    (padding.PKCS1v15, hashes.SHA224, Mechanism.SHA224_RSA_PKCS, SignatureMethod.RSA_SHA224),
    (padding.PKCS1v15, hashes.SHA256, Mechanism.SHA256_RSA_PKCS, SignatureMethod.RSA_SHA256),
    (padding.PKCS1v15, hashes.SHA384, Mechanism.SHA384_RSA_PKCS, SignatureMethod.RSA_SHA384),
    (padding.PKCS1v15, hashes.SHA512, Mechanism.SHA512_RSA_PKCS, SignatureMethod.RSA_SHA512),
]

def map_p11_mechanism(x509_cert: Certificate) -> Mechanism:
    cert_sig_alg = x509_cert.signature_algorithm_parameters
    cert_hash_alg = x509_cert.signature_hash_algorithm

    for map_entry in _MAPPING:
        sig_alg, hash_alg, p11_mechanism, _ = map_entry

        if isinstance(cert_sig_alg, sig_alg) and isinstance(cert_hash_alg, hash_alg):
            return p11_mechanism

    raise RuntimeError(f"Unsupported: signature_algorithm={cert_sig_alg}; hash_algorithm={cert_hash_alg}")


def map_signxml_algorithm(x509_cert: Certificate) -> SignatureMethod:
    cert_sig_alg = x509_cert.signature_algorithm_parameters
    cert_hash_alg = x509_cert.signature_hash_algorithm

    for map_entry in _MAPPING:
        sig_alg, hash_alg, _, signxml_method = map_entry

        if isinstance(cert_sig_alg, sig_alg) and isinstance(cert_hash_alg, hash_alg):
            return signxml_method

    raise RuntimeError(f"Unsupported: signature_algorithm={cert_sig_alg}; hash_algorithm={cert_hash_alg}")
