from enum import Enum

import requests
import signxml
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.x509 import Certificate
from lxml import etree
from signxml.xades import XAdESVerifier, XAdESSigner, XAdESDataObjectFormat

from pyksef.p11._alg_mapping import map_signxml_algorithm
from pyksef.p11._privkey import P11ECPrivateKey, P11RSAPrivateKey


class SubjectIdentifierType(Enum):
    certificateSubject = "certificateSubject"
    certificateFingerprint = "certificateFingerprint"


class PEMPrivateKey:
    key_pem: bytes
    passphrase: bytes | None

    def __init__(self, key_pem: bytes, passphrase: bytes | None):
        self.key_pem = key_pem
        self.passphrase = passphrase


def ksef_auth_xades(
        *,
        api_base_url: str,
        cert: Certificate,
        key: P11ECPrivateKey | P11RSAPrivateKey | PEMPrivateKey,
        target_nip: str,
        identifier_type: SubjectIdentifierType = SubjectIdentifierType.certificateSubject
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
            <SubjectIdentifierType>{identifier_type.value}</SubjectIdentifierType>
        </AuthTokenRequest>""".encode("utf-8")
        return etree.fromstring(data)

    def map_key_to_signer_params(key: P11ECPrivateKey | P11RSAPrivateKey | PEMPrivateKey):
        if isinstance(key, PEMPrivateKey):
            return {"key": key.key_pem, "passphrase": key.passphrase}

        return {"key": key}

    challenge = get_challenge()["challenge"]
    auth_xml_root = build_xml(challenge, target_nip, identifier_type)

    cert_pem = cert.public_bytes(Encoding.PEM).decode("utf-8")

    data_object_format = XAdESDataObjectFormat(Description="Uwierzytelnienie do KSeF", MimeType="application/xml")
    signer = XAdESSigner(method=signxml.methods.enveloped, signature_algorithm=map_signxml_algorithm(cert),
                         data_object_format=data_object_format)
    signed_root = signer.sign(auth_xml_root, cert=cert_pem, **map_key_to_signer_params(key))

    # perform a sanity check whether the produced signature is really correct
    verifier = XAdESVerifier()
    verify_results = verifier.verify(signed_root, x509_cert=cert_pem, expect_references=3)

    if len(verify_results) != 3 or not any(o.signed_data for o in verify_results):
        raise RuntimeError("Failed to verify signature. Wrong private key?")

    signed_txt = etree.tostring(signed_root, pretty_print=True)
    return get_token(api_base_url, signed_txt)
