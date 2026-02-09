from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.x509 import Certificate

from pyksef.p11._lib_wrapper import PKCS11Lib
from pyksef.p11._privkey.key_ec import P11ECPrivateKey
from pyksef.p11._privkey.key_rsa import P11RSAPrivateKey


def create_p11_private_key(p11_lib: PKCS11Lib, x509_cert: Certificate) -> P11ECPrivateKey | P11RSAPrivateKey:
    cert_sig_alg = x509_cert.signature_algorithm_parameters

    if isinstance(cert_sig_alg, ec.ECDSA):
        return P11ECPrivateKey(p11_lib, x509_cert)
    elif isinstance(cert_sig_alg, padding.PKCS1v15):
        return P11RSAPrivateKey(p11_lib, x509_cert)

    raise ValueError("Unsupported ECDSA signature algorithm: " + repr(cert_sig_alg))
