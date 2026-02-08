import argparse
import json
from enum import Enum

import requests
import signxml
from lxml import etree
from signxml import SignatureMethod
from signxml.xades import XAdESVerifier, XAdESSigner

PROD_API_BASE = "https://api.ksef.mf.gov.pl/v2"

class SubjectIdentifierType(Enum):
    certificateSubject = "certificateSubject"
    certificateFingerprint = "certificateFingerprint"

def ksef_xades_auth(
        *,
        api_base_url: str,
        cert_pem: str,
        key_pem: str,
        key_passphrase: bytes | None,
        target_nip: str,
        identifier_type: SubjectIdentifierType=SubjectIdentifierType.certificateSubject
):
    def get_challenge() -> dict:
        res = requests.post(f"{api_base_url}/auth/challenge")
        res.raise_for_status()
        return res.json()

    def get_token(api_base: str, signed_auth_xml: bytes):
        res = requests.post(
            f"{api_base}/auth/xades-signature",
            headers={"Content-Type": "application/xml"},
            data=signed_auth_xml)
        res.raise_for_status()

        return res.json()

    def build_xml(challenge: str, target_nip: str, identifier_type: SubjectIdentifierType):
        data = f"""<?xml version="1.0" encoding="utf-8"?>
        <AuthTokenRequest xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://ksef.mf.gov.pl/auth/token/2.0">
            <Challenge>{challenge}</Challenge>
            <ContextIdentifier>
                <Nip>{target_nip}</Nip>
            </ContextIdentifier>
            <SubjectIdentifierType>{identifier_type}</SubjectIdentifierType>
        </AuthTokenRequest>""".encode("utf-8")
        return etree.fromstring(data)

    challenge = get_challenge()["challenge"]
    auth_xml_root = build_xml(challenge, target_nip, identifier_type)

    signer = XAdESSigner(method=signxml.methods.enveloped, signature_algorithm=SignatureMethod.ECDSA_SHA256)
    signed_root = signer.sign(auth_xml_root, cert=cert_pem, key=key_pem, passphrase=key_passphrase)

    # perform a sanity check whether the produced signature is really correct
    verifier = XAdESVerifier()
    verify_results = verifier.verify(signed_root, x509_cert=cert_pem, expect_references=3)

    if len(verify_results) != 3 or not any(o.signed_data for o in verify_results):
        raise RuntimeError("Failed to verify signature.")

    signed_txt = etree.tostring(signed_root, pretty_print=True)
    return get_token(api_base_url, signed_txt)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Obtain KSeF session token by doing XAdES certificate authentication.")

    parser.add_argument("--api-base-url", default=PROD_API_BASE, help=f"Base URL for the API. Default: {PROD_API_BASE}")
    parser.add_argument("--cert-file", required=True, help="KSeF Certificate file path")
    parser.add_argument("--key-file", required=True, help="KSeF Key file path")
    parser.add_argument("--key-passphrase", help="Passphrase to decrypt the key file")
    parser.add_argument("--target-nip", required=True, help="Target NIP (Tax ID) to authenticate against")
    parser.add_argument(
        "--identifier-type",
        choices=["certificateSubject", "certificateFingerprint"],
        default="certificateSubject",
        help="Accepted values: 'certificateSubject' or 'certificateFingerprint'. Default: 'certificateSubject'.")

    args = parser.parse_args()

    with open(args.cert_file, "r") as f:
        cert_pem = f.read()

    with open(args.key_file, "r") as f:
        key_pem = f.read()

    if args.key_passphrase:
        passphrase = args.key_passphrase.encode("utf-8")
    else:
        passphrase = None

    res = ksef_xades_auth(
        api_base_url=PROD_API_BASE,
        cert_pem=cert_pem,
        key_pem=key_pem,
        key_passphrase=passphrase,
        target_nip=args.target_nip,
        identifier_type=args.identifier_type
    )

    print(json.dumps(res))
