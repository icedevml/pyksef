import argparse
import json

from pyksef import ksef_auth_xades, SubjectIdentifierType, PEMPrivateKey
from pyksef.x509 import load_pem_x509_certificate, Certificate


def ksef_auth_file(
        *,
        cert: Certificate,
        key_pem: bytes,
        key_passphrase: bytes | None,
        api_base_url: str,
        target_nip: str):
    key = PEMPrivateKey(key_pem, key_passphrase)

    res = ksef_auth_xades(
        api_base_url=api_base_url,
        cert=cert,
        key=key,
        target_nip=target_nip,
        identifier_type=SubjectIdentifierType.certificateSubject
    )

    print(json.dumps(res))


def cli():
    parser = argparse.ArgumentParser(description="Perform KSeF authentication through key file.")

    parser.add_argument("--cert-file", required=True, help="Path to the X509 certificate file (PEM).")
    parser.add_argument("--key-file", required=True, help="Path to the key file (PEM).")
    parser.add_argument("--key-passphrase", help="Passphrase to decrypt the key file.")
    parser.add_argument("--api-base-url", default="https://api.ksef.mf.gov.pl/v2", help="KSeF API base url. Default: https://api.ksef.mf.gov.pl/v2")
    parser.add_argument("--target-nip", required=True, help="Target NIP (Tax ID) to authenticate against.")
    args = parser.parse_args()

    with open(args.cert_file, "rb") as f:
        cert = load_pem_x509_certificate(f.read())

    with open(args.key_file, 'rb') as f:
        key_pem = f.read()

    key_passphrase = None

    if args.key_passphrase:
        key_passphrase = args.key_passphrase.encode("utf-8")

    ksef_auth_file(
        cert=cert,
        key_pem=key_pem,
        key_passphrase=key_passphrase,
        api_base_url=args.api_base_url,
        target_nip=args.target_nip
    )


if __name__ == "__main__":
    cli()
