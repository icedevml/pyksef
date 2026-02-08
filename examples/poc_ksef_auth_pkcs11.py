import binascii

from pyksef import ksef_auth_xades, SubjectIdentifierType
from pyksef.p11 import PKCS11Lib, get_leaf_certificate, create_p11_private_key

PROD_API_BASE_URL = "https://api.ksef.mf.gov.pl/v2"

# load PKCS#11 library for CryptoCard Graphite (note that any qualified signature/seal issuer is supported)
lib = PKCS11Lib("C:\\Program Files\\Krajowa Izba Rozliczeniowa S.A\\Szafir 2.0\\bin\\CCGraphiteP11p.x64.dll")
# set token label and PIN; if you don't know your token_label, check it using cli_p11_list_tokens.py tool
lib.set_token(token_label="PKI Token 2 (QSCD)", user_pin="123456")
# set private key ID; if you don't know your key_id, check it using cli_p11_list_objects.py tool
lib.set_private_key(key_id=binascii.unhexlify("6572df736d642974a2bab6ddba753aefb89afcce"))

# download the signer's certificate from the signer device directly
cert = get_leaf_certificate(o.x509_cert for o in lib.get_certificates())

# alternatively, you may just read the signer's certificate from file
# ---
# with open("ksef.crt", "rb") as f:
#     cert = load_pem_x509_certificate(cert_pem_bytes)
# ---

res = ksef_auth_xades(
    api_base_url=PROD_API_BASE_URL,
    cert=cert,
    key=create_p11_private_key(lib, cert),
    target_nip="5421234567",
    identifier_type=SubjectIdentifierType.certificateSubject
)

print(res)
