from typing import Iterable, Generator

from cryptography.x509 import Certificate, BasicConstraints


def get_leaf_certificates(certs: Iterable[Certificate]) -> Generator[Certificate, None, None]:
    for cert in certs:
        ext = cert.extensions.get_extension_for_class(BasicConstraints)
        if not ext.value.ca:
            yield cert


def get_leaf_certificate(certs: Iterable[Certificate]) -> Certificate:
    leafs = list(get_leaf_certificates(certs))

    if len(leafs) == 0:
        raise ValueError("No leaf certificates found.")
    elif len(leafs) > 1:
        raise ValueError("More than one leaf certificates found.")

    return leafs[0]
