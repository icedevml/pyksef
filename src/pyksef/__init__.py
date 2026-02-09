"""Python KSeF Authentication Library (for PKCS#11 and local private keys)"""

__version__ = "0.3.3"

from pyksef.auth import ksef_auth_xades

__all__ = [
    "ksef_auth_xades"
]
