# Python KSeF Authentication Library (for PKCS#11 and local private keys)

> [!NOTE]  
> PL: Biblioteka do języka Python obsługująca logowanie do KSeF z użyciem dowolnego klucza prywatnego obsługującego interfejs PKCS#11 – kwalifikowane podpisy i pieczęci elektroniczne (na karcie, tokenie USB lub w formie HSM), a także certyfikaty wydane przez KSeF, do których klucze prywatne przechowywane są na HSMie (np. YubiHSM, YubiKey, Google Cloud KMS). Obsługuje również klasyczne uwierzytelnianie kluczem przechowywanym lokalnie na dysku twardym w pliku `.key` (format PEM).

Supported features:

* Authentication using private keys available through PKCS#11 interface:
  * Qualified signature or qualified seal issued on a physical device,
  * KSeF Certificate hosted on a HSM (e.g. YubiHSM, YubiKey, Google Cloud KMS).
* Authentication using certificate and private key stored as PEM files on local hard disk.

## Installation

Library available on PyPi: [pyksef](https://pypi.org/project/pyksef/)

```commandline
pip3 install pyksef
```

## CLI Usage

### List available PKCS#11 tokens
Command:
```bash
p11_list_tokens \
    --pkcs11-dll "C:\Program Files\Krajowa Izba Rozliczeniowa S.A\Szafir 2.0\bin\CCGraphiteP11p.x64.dll"
```
Example output:
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
    --token-serial "31333132303030313233343536373839"
```
Example output:
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
    --output certificates
```
Example output:
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
    --context-id-type nip \
    --context-id 5421234567
```
Example output:
```json
{"referenceNumber": "XXXXXXXX-XX-XXXXXXXXXX-XXXXXXXXXX-XX", "authenticationToken": {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "validUntil": "2026-02-04T15:20:15.6254824+00:00"}}
```

### Perform KSeF authentication using certificate/private key file pair stored on disk
Command:
```bash
ksef_auth_file \
    --cert-file ksef.crt \
    --key-file ksf.key \
    --context-id-type nip \
    --context-id 5421234567
```
Example output:
```json
{"referenceNumber": "XXXXXXXX-XX-XXXXXXXXXX-XXXXXXXXXX-XX", "authenticationToken": {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "validUntil": "2026-02-04T15:20:15.6254824+00:00"}}
```

## Usage via Python

### PKCS#11 List tokens available with certain provider

```python
from pyksef.p11 import PKCS11Lib

# load PKCS#11 library for CryptoCard Graphite (note that any qualified signature/seal issuer is supported)
PKCS11_DLL_PATH = "C:\\Program Files\\Krajowa Izba Rozliczeniowa S.A\\Szafir 2.0\\bin\\CCGraphiteP11p.x64.dll"

lib = PKCS11Lib(PKCS11_DLL_PATH)
for token in lib.get_tokens():
    print(token)
```

Example output:
```
TokenRecord(slot=<Slot (slotID=2 flags=7)>, label='PKI Token 1 (Primary)', serial='31333132303030313233343536373839', manufacturer_id='CryptoTech P.S.A.', model='CCGraphitePro', hardware_version=(0, 0), firmware_version=(0, 0), flags=<TokenFlag.LOGIN_REQUIRED|USER_PIN_INITIALIZED|TOKEN_INITIALIZED: 1036>)
TokenRecord(slot=<Slot (slotID=3 flags=7)>, label='PKI Token 2 (QSCD)', serial='31333132303030313233343536373839', manufacturer_id='CryptoTech P.S.A.', model='CCGraphitePro', hardware_version=(0, 0), firmware_version=(0, 0), flags=<TokenFlag.WRITE_PROTECTED|LOGIN_REQUIRED|USER_PIN_INITIALIZED|TOKEN_INITIALIZED: 1038>)
```

### PKCS#11 List private keys/certificates available with certain token

```python
import getpass

from pyksef.p11 import PKCS11Lib

PKCS11_DLL_PATH = "C:\\Program Files\\Krajowa Izba Rozliczeniowa S.A\\Szafir 2.0\\bin\\CCGraphiteP11p.x64.dll"
TOKEN_LABEL = "PKI Token 2 (QSCD)"
USER_PIN = getpass.getpass("User PIN: ")

lib = PKCS11Lib(PKCS11_DLL_PATH)
lib.set_token(token_label=TOKEN_LABEL, user_pin=USER_PIN)

for certificate in lib.get_certificates():
    print(certificate)

for private_key in lib.get_private_keys():
    print(private_key)
```

Example output:
```
CertificateRecord(x509_cert=<Certificate(subject=<Name(C=PL,2.5.4.5=PNOPL-12345678900,CN=Jan Kowalski,2.5.4.42=Jan,2.5.4.4=Kowalski)>, ...)>)
PrivateKeyRecord(label='No Friendly Name Available', id='6572df736d642974a2bab6ddba753aefb89afcce', key_type=<KeyType.RSA>)
```

### PKCS#11 Authentication

```python
import binascii
import getpass
import json

from pyksef import ksef_auth_xades
from pyksef.auth.identifier import ContextIdentifier, ContextIdentifierType, SubjectIdentifierType
from pyksef.auth.state import ksef_poll_auth_finalized
from pyksef.p11 import create_p11_private_key, PKCS11Lib, get_leaf_certificate
from pyksef.x509 import load_pem_x509_certificate


# PKCS#11 Token parameters
PKCS11_DLL_PATH = "C:\\Program Files\\Krajowa Izba Rozliczeniowa S.A\\Szafir 2.0\\bin\\CCGraphiteP11p.x64.dll"
TOKEN_LABEL = "PKI Token 2 (QSCD)"
USER_PIN = getpass.getpass("User PIN: ")
PRIVATE_KEY_ID = "6572df736d642974a2bab6ddba753aefb89afcce"

# Authentication parameters
CONTEXT_ID = ContextIdentifier(type=ContextIdentifierType.nip, value="5421234567")
SUBJECT_ID_TYPE = SubjectIdentifierType.certificateSubject

# API URL
PROD_API_BASE_URL = "https://api.ksef.mf.gov.pl/v2"

# ---

lib = PKCS11Lib(PKCS11_DLL_PATH)
lib.set_token(token_label=TOKEN_LABEL, user_pin=USER_PIN)
lib.set_private_key(key_id=binascii.unhexlify(PRIVATE_KEY_ID))

# download the signer's certificate from the signer device directly
cert = get_leaf_certificate(o.x509_cert for o in lib.get_certificates())

# alternatively, you may just read the signer's certificate from file
# ---
# with open("ksef.crt", "rb") as f:
#     cert = load_pem_x509_certificate(cert_pem_bytes)
# ---

# perform KSeF authentication using PKCS#11 private key
auth_res = ksef_auth_xades(
  api_base_url=PROD_API_BASE_URL,
  cert=cert,
  key=create_p11_private_key(lib, cert),
  context_id=CONTEXT_ID,
  subject_id_type=SUBJECT_ID_TYPE,
)

# poll authentication state and redeem the actual token
auth_state = ksef_poll_auth_finalized(
    api_base_url=PROD_API_BASE_URL,
    reference_number=auth_res["referenceNumber"],
    authentication_token=auth_res["authenticationToken"]["token"]
)

print(json.dumps({
    "ksefAuthPKCS11Result": auth_res,
    "ksefPollAuthFinalizedResult": auth_state,
}, indent=4))
```
Example output:
```json
{
    "ksefAuthPKCS11Result": {
        "referenceNumber": "XXXXXXXX-XX-XXXXXXXXXX-XXXXXXXXXX-XX",
        "authenticationToken": {
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "validUntil": "2026-02-09T16:08:59.2602376+00:00"
        }
    },
    "ksefPollAuthFinalizedResult": {
        "redeemResult": {
            "accessToken": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                "validUntil": "2026-02-09T15:38:58.1201962+00:00"
            },
            "refreshToken": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                "validUntil": "2026-02-16T15:23:58.1201962+00:00"
            }
        },
        "authState": {
            "startDate": "2026-02-09T15:23:58.1401992+00:00",
            "authenticationMethod": "QualifiedSignature",
            "status": {
                "code": 200,
                "description": "Uwierzytelnianie zako\u0144czone sukcesem"
            },
            "isTokenRedeemed": false
        }
    }
}
```

### Authentication with private key on local disk

```python
import getpass
import json

from pyksef import ksef_auth_xades
from pyksef.auth.identifier import ContextIdentifier, ContextIdentifierType, SubjectIdentifierType
from pyksef.auth.local_key import PEMPrivateKey
from pyksef.auth.state import ksef_poll_auth_finalized
from pyksef.x509 import load_pem_x509_certificate


# Certificate/key file parameters
PEM_CERT_FILENAME = "_private/ksef.crt"
PEM_KEY_FILENAME = "_private/ksef.key"
PEM_PASSPHRASE = getpass.getpass("PEM Passphrase: ")

# Authentication parameters
CONTEXT_ID = ContextIdentifier(type=ContextIdentifierType.nip, value="5421234567")
SUBJECT_ID_TYPE = SubjectIdentifierType.certificateSubject

# API URL
PROD_API_BASE_URL = "https://api.ksef.mf.gov.pl/v2"

# ---

# load X.509 certificate from file
with open(PEM_CERT_FILENAME, 'rb') as f:
    cert = load_pem_x509_certificate(f.read())

# load X.509 key from file
with open(PEM_KEY_FILENAME, 'rb') as f:
    key_pem = f.read()

# construct PEMPrivateKey object with file contents and passphrase to decrypt the key
key = PEMPrivateKey(key_pem, PEM_PASSPHRASE.encode("utf-8"))

# perform KSeF authentication with PEM certificate/key file
auth_res = ksef_auth_xades(
    api_base_url=PROD_API_BASE_URL,
    cert=cert,
    key=key,
    context_id=CONTEXT_ID,
    subject_id_type=SUBJECT_ID_TYPE,
)

# poll authentication state and redeem the actual token
auth_state = ksef_poll_auth_finalized(
    api_base_url=PROD_API_BASE_URL,
    reference_number=auth_res["referenceNumber"],
    authentication_token=auth_res["authenticationToken"]["token"]
)

print(json.dumps({
    "ksefAuthFileResult": auth_res,
    "ksefPollAuthFinalizedResult": auth_state,
}, indent=4))
```
Example output:
```json
{
    "ksefAuthPKCS11Result": {
        "referenceNumber": "XXXXXXXX-XX-XXXXXXXXXX-XXXXXXXXXX-XX",
        "authenticationToken": {
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "validUntil": "2026-02-09T16:08:59.2602376+00:00"
        }
    },
    "ksefPollAuthFinalizedResult": {
        "redeemResult": {
            "accessToken": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                "validUntil": "2026-02-09T15:38:58.1201962+00:00"
            },
            "refreshToken": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                "validUntil": "2026-02-16T15:23:58.1201962+00:00"
            }
        },
        "authState": {
            "startDate": "2026-02-09T15:23:58.1401992+00:00",
            "authenticationMethod": "QualifiedSignature",
            "status": {
                "code": 200,
                "description": "Uwierzytelnianie zako\u0144czone sukcesem"
            },
            "isTokenRedeemed": false
        }
    }
}
```

## Troubleshooting

If you see the following exception even though the DLL physically exists at the path indicated:

```
pkcs11.exceptions.PKCS11Error: OS exception while loading <file path>.dll: The specified module could not be found.
```

please check if your `PATH` environment variable is set correctly. Your PKCS#11 DLL might depend on some auxiliary DLLs that are unavailable.
