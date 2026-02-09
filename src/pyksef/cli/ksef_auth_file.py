import argparse
import getpass
import json

from pyksef import ksef_auth_xades
from pyksef.auth.identifier import ContextIdentifier, ContextIdentifierType, SubjectIdentifierType
from pyksef.auth.local_key import PEMPrivateKey
from pyksef.auth.state import ksef_poll_auth_finalized
from pyksef.x509 import load_pem_x509_certificate, Certificate


def ksef_auth_file(
        *,
        cert: Certificate,
        key_pem: bytes,
        key_passphrase: bytes | None,
        api_base_url: str,
        context_id: ContextIdentifier,
        subject_id_type: SubjectIdentifierType):
    key = PEMPrivateKey(key_pem, key_passphrase)

    return ksef_auth_xades(
        api_base_url=api_base_url,
        cert=cert,
        key=key,
        context_id=context_id,
        subject_id_type=subject_id_type,
    )


def cli():
    parser = argparse.ArgumentParser(description="Perform KSeF authentication through key file.")

    parser.add_argument("--cert-file", required=True, help="Path to the X509 certificate file (PEM).")
    parser.add_argument("--key-file", required=True, help="Path to the key file (PEM).")
    parser.add_argument("--key-passphrase",
                        help="Optional: Passphrase to decrypt the key file. You will be interactively prompted for "
                             "a passphrase if this argument is not provided.")
    parser.add_argument("--api-base-url", default="https://api.ksef.mf.gov.pl/v2",
                        help="KSeF API base url. Default: https://api.ksef.mf.gov.pl/v2")
    parser.add_argument("--context-id-type", default="nip",
                        help="Optional: 'nip' (default), 'nipVatUe', or 'internalId'.")
    parser.add_argument("--context-id", required=True, help="Context identifier to authenticate against.")
    parser.add_argument("--subject-id-type", default="certificateSubject",
                        help="Optional: Subject identifier type: 'certificateSubject' (default) "
                             "or 'certificateFingerprint'.")
    args = parser.parse_args()

    context_id = ContextIdentifier(
        type=ContextIdentifierType[args.context_id_type],
        value=args.context_id
    )

    with open(args.cert_file, "rb") as f:
        cert = load_pem_x509_certificate(f.read())

    with open(args.key_file, 'rb') as f:
        key_pem = f.read()

    key_passphrase = None

    if args.key_passphrase:
        key_passphrase = args.key_passphrase.encode("utf-8")
    else:
        entered_pass = getpass.getpass("PEM Passphrase: ")

        if entered_pass:
            key_passphrase = entered_pass.encode("utf-8")

    auth_res = ksef_auth_file(
        cert=cert,
        key_pem=key_pem,
        key_passphrase=key_passphrase,
        api_base_url=args.api_base_url,
        context_id=context_id,
        subject_id_type=SubjectIdentifierType[args.subject_id_type]
    )

    auth_state = ksef_poll_auth_finalized(
        api_base_url=args.api_base_url,
        reference_number=auth_res["referenceNumber"],
        authentication_token=auth_res["authenticationToken"]["token"]
    )

    print(json.dumps({
        "ksefAuthInitResult": auth_res,
        "ksefPollAuthFinalizedResult": auth_state,
    }, indent=4))


if __name__ == "__main__":
    cli()
