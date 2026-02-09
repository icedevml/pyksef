import argparse
import binascii
import getpass
import json

from pyksef import ksef_auth_xades, SubjectIdentifierType
from pyksef.p11 import create_p11_private_key, PKCS11Lib, get_leaf_certificate
from pyksef.x509 import Certificate, load_pem_x509_certificate


def ksef_auth_pkcs11(
        *,
        pkcs11_dll: str,
        token_label: str | None,
        token_serial: bytes | None,
        user_pin: str,
        key_id: bytes | None,
        key_label: str | None,
        cert: Certificate | None,
        api_base_url: str,
        target_nip: str):
    lib = PKCS11Lib(pkcs11_dll)
    lib.set_token(token_label=token_label, token_serial=token_serial, user_pin=user_pin)
    lib.set_private_key(key_id=key_id, key_label=key_label)

    # if certificate was not provided explicitly, we will try to load it from the token itself
    if not cert:
        cert = get_leaf_certificate(o.x509_cert for o in lib.get_certificates())

    res = ksef_auth_xades(
        api_base_url=api_base_url,
        cert=cert,
        key=create_p11_private_key(lib, cert),
        target_nip=target_nip,
        identifier_type=SubjectIdentifierType.certificateSubject
    )

    print(json.dumps(res))


def cli():
    parser = argparse.ArgumentParser(description="Perform KSeF authentication through PKCS#11 signer.")

    parser.add_argument("--pkcs11-dll", required=True, help="Path to PKCS#11 Provider DLL library.")
    parser.add_argument("--token-label", help="Token's label.")
    parser.add_argument("--token-serial", help="Token's serial number (hex).")
    parser.add_argument("--key-id", help="Private key ID (hex).")
    parser.add_argument("--key-label", help="Private key label.")
    parser.add_argument("--user-pin", help="Optional: User PIN to login to the token. You will be interactively prompted for PIN if this argument is not provided.")
    parser.add_argument("--cert-file", help="Optional: File path for X.509 PEM Certificate file. If not provided, we will try to load it from the token (device) itself.")
    parser.add_argument("--api-base-url", default="https://api.ksef.mf.gov.pl/v2", help="Optional: KSeF API base url. Default: https://api.ksef.mf.gov.pl/v2")
    parser.add_argument("--target-nip", required=True, help="Target NIP (Tax ID) to authenticate against.")
    args = parser.parse_args()

    token_serial = None
    key_id = None
    cert = None

    if args.user_pin:
        user_pin = args.user_pin
    else:
        user_pin = getpass.getpass("User PIN: ")

    if args.token_serial:
        token_serial = binascii.unhexlify(args.token_serial)

    if args.key_id:
        key_id = binascii.unhexlify(args.key_id)

    if args.cert_file:
        with open(args.cert_file, "rb") as f:
            cert = load_pem_x509_certificate(f.read())

    ksef_auth_pkcs11(
        pkcs11_dll=args.pkcs11_dll,
        token_label=args.token_label,
        token_serial=token_serial,
        key_id=key_id,
        key_label=args.key_label,
        user_pin=user_pin,
        cert=cert,
        api_base_url=args.api_base_url,
        target_nip=args.target_nip
    )


if __name__ == "__main__":
    cli()
