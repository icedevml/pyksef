import argparse
import binascii
import getpass

from cryptography.hazmat.primitives._serialization import Encoding

from pyksef.p11 import PKCS11Lib


def p11_list_certificates(pkcs11_dll_path: str, token_label: str, token_serial: bytes, user_pin: str):
    lib = PKCS11Lib(pkcs11_dll_path)
    lib.set_token(
        token_label=token_label,
        token_serial=token_serial,
        user_pin=user_pin)

    for cert in lib.get_certificates():
        yield cert


def p11_list_private_keys(pkcs11_dll_path: str, token_label: str, token_serial: bytes, user_pin: str):
    lib = PKCS11Lib(pkcs11_dll_path)
    lib.set_token(
        token_label=token_label,
        token_serial=token_serial,
        user_pin=user_pin)

    for private_key in lib.get_private_keys():
        yield private_key


def cli():
    parser = argparse.ArgumentParser(
        description="Fetch certificates and private keys available with certain PKCS#11 token.")

    parser.add_argument("--pkcs11-dll", required=True, help="Path to PKCS#11 Provider DLL library.")
    parser.add_argument("--token-label", help="Token's label.")
    parser.add_argument("--token-serial", help="Token's serial number (hex).")
    parser.add_argument("--user-pin", help="Optional: User PIN to login to the token. You will be interactively prompted for PIN if this argument is not provided.")
    parser.add_argument("--output", choices=["list", "certificates"], default="list", help="Output type. For 'list' will output a list of certificates and private keys available with certain PKCS#11 token. For 'certificates' it will dump all available certificates in the PEM format.")
    args = parser.parse_args()

    token_serial = None

    if args.user_pin:
        user_pin = args.user_pin
    else:
        user_pin = getpass.getpass("User PIN: ")

    if args.token_serial:
        token_serial = binascii.unhexlify(args.token_serial)

    if args.output == "list":
        for cert in p11_list_certificates(args.pkcs11_dll, args.token_label, token_serial, user_pin):
            print(cert)

        for private_key in p11_list_private_keys(args.pkcs11_dll, args.token_label, token_serial, user_pin):
            print(private_key)
    elif args.output == "certificates":
        for cert in p11_list_certificates(args.pkcs11_dll, args.token_label, token_serial, user_pin):
            print(cert.x509_cert.public_bytes(Encoding.PEM).decode("utf-8"))


if __name__ == "__main__":
    cli()
