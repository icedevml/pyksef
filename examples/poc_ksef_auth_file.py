from cryptography.x509 import load_pem_x509_certificate

from pyksef import ksef_auth_xades, PEMPrivateKey, SubjectIdentifierType

PROD_API_BASE_URL = "https://api.ksef.mf.gov.pl/v2"

# load X.509 certificate from file
with open('_private/ksef.crt', 'rb') as f:
    cert = load_pem_x509_certificate(f.read())

# load X.509 key from file
with open('_private/ksef.key', 'rb') as f:
    key_pem = f.read()

# construct PEMPrivateKey object with file contents and passphrase to decrypt the key
key = PEMPrivateKey(key_pem, b"MyPassword54321!!")

# perform KSeF authentication
res = ksef_auth_xades(
    api_base_url=PROD_API_BASE_URL,
    cert=cert,
    key=key,
    target_nip="5421234567",
    identifier_type=SubjectIdentifierType.certificateSubject
)

print(res)
