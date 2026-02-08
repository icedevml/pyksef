import argparse

from pyksef.p11 import PKCS11Lib


def p11_list_tokens(pkcs11_dll_path: str):
    lib = PKCS11Lib(pkcs11_dll_path)
    return lib.get_tokens()


def cli():
    parser = argparse.ArgumentParser(
        description="List PKCS#11 tokens available with certain PKCS#11 provider.")

    parser.add_argument("--pkcs11-dll", required=True, help="Path to PKCS#11 Provider DLL library.")
    args = parser.parse_args()

    for token in p11_list_tokens(args.pkcs11_dll):
        print(token)


if __name__ == "__main__":
    cli()
