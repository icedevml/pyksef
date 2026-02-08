# Python KSeF XAdES Authentication

Supported features:

* Authentication using private keys available through PKCS#11 interface:
  * Qualified signature or qualified seal issued on a physical device,
  * KSeF Certificate hosted on a HSM (e.g. YubiHSM, YubiKey, Google Cloud KMS).
* Authentication using certificate and private key stored as PEM files on local hard disk.

## CLI Usage

```commandline
pip3 install pyksef
```

### List available PKCS#11 tokens
Command:
```bash
p11_list_tokens \
    --pkcs11-dll "C:\Program Files\Krajowa Izba Rozliczeniowa S.A\Szafir 2.0\bin\CCGraphiteP11p.x64.dll"
```
Output:
```
TokenRecord(slot=<Slot (slotID=2 flags=7)>, label='PKI Token 1 (Primary)', serial='31333132303030313233343536373839', manufacturer_id='CryptoTech P.S.A.', model='CCGraphitePro', hardware_version=(0, 0), firmware_version=(0, 0), flags=<TokenFlag.LOGIN_REQUIRED|USER_PIN_INITIALIZED|TOKEN_INITIALIZED: 1036>)
TokenRecord(slot=<Slot (slotID=3 flags=7)>, label='PKI Token 2 (QSCD)', serial='31333132303030313233343536373839', manufacturer_id='CryptoTech P.S.A.', model='CCGraphitePro', hardware_version=(0, 0), firmware_version=(0, 0), flags=<TokenFlag.WRITE_PROTECTED|LOGIN_REQUIRED|USER_PIN_INITIALIZED|TOKEN_INITIALIZED: 1038>)
```

### List available private keys/certificates for PKCS#11 token
Command:
```bash
p11_list_objects \
    --pkcs11-dll "C:\Program Files\Krajowa Izba Rozliczeniowa S.A\Szafir 2.0\bin\CCGraphiteP11p.x64.dll" \
    --token-label "PKI Token 2 (QSCD)" \
    --token-serial "31333132303030313233343536373839" \
    --user-pin 123456                                                                                                                                                                                                     
```
Output:
```
CertificateRecord(x509_cert=<Certificate(subject=<Name(C=PL,2.5.4.5=PNOPL-12345678900,CN=Jan Kowalski,2.5.4.42=Jan,2.5.4.4=Kowalski)>, ...)>)
PrivateKeyRecord(label='No Friendly Name Available', id='6572df736d642974a2bab6ddba753aefb89afcce', key_type=<KeyType.RSA>)
```

### Fetch certificates stored on a PKCS#11 token
Command:
```bash
p11_list_objects \
    --pkcs11-dll "C:\Program Files\Krajowa Izba Rozliczeniowa S.A\Szafir 2.0\bin\CCGraphiteP11p.x64.dll" \
    --token-label "PKI Token 2 (QSCD)" \
    --token-serial "31333132303030313233343536373839" \
    --user-pin 123456 \
    --output certificates
```
Output:
```
-----BEGIN CERTIFICATE-----
MIIHe...
-----END CERTIFICATE-----
```

### Perform KSeF authentication using private key available through PKCS#11
Command:
```bash
ksef_auth_pkcs11 \
    --pkcs11-dll "C:\Program Files\Krajowa Izba Rozliczeniowa S.A\Szafir 2.0\bin\CCGraphiteP11p.x64.dll" \
    --token-label "PKI Token 2 (QSCD)" \
    --key-id 6572df736d642974a2bab6ddba753aefb89afcce \
    --user-pin 123456 \
    --target-nip 5421234567
```
Output:
```json
{"referenceNumber": "XXXXXXXX-XX-XXXXXXXXXX-XXXXXXXXXX-XX", "authenticationToken": {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "validUntil": "2026-02-04T15:20:15.6254824+00:00"}}
```

### Perform KSeF authentication using certificate/private key file pair stored on disk
Command:
```bash
ksef_auth_file \
    --cert-file ksef.crt \
    --key-file ksf.key \
    --key-passphrase "MyPassword54321!!" \
    --target-nip 5421234567
```
Output:
```json
{"referenceNumber": "XXXXXXXX-XX-XXXXXXXXXX-XXXXXXXXXX-XX", "authenticationToken": {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "validUntil": "2026-02-04T15:20:15.6254824+00:00"}}
```

## Usage via Python

### PKCS#11 Authentication

```python
import binascii

from pyksef import ksef_auth_xades, SubjectIdentifierType
from pyksef.p11 import PKCS11Lib, get_leaf_certificate, create_p11_private_key

PROD_API_BASE_URL = "https://api.ksef.mf.gov.pl/v2"

# load PKCS#11 library for CryptoCard Graphite (note that any qualified signature/seal issuer is supported)
lib = PKCS11Lib("C:\\Program Files\\Krajowa Izba Rozliczeniowa S.A\\Szafir 2.0\\bin\\CCGraphiteP11p.x64.dll")
# set token label and PIN; if you don't know your token_label, check it using cli_p11_list_tokens.py tool
# or invoke `lib.get_tokens()` programmatically
lib.set_token(token_label="PKI Token 2 (QSCD)", user_pin="123456")
# set private key ID; if you don't know your key_id, check it using cli_p11_list_objects.py tool
# or invoke `lib.get_private_keys()` programmatically
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
```

### Authentication with private key on local disk

```python
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
```
