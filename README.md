# Python KSeF XAdES Authentication

## CLI usage
Command:
```
python ksef_xades_auth.py \
 --cert-file=ksef.crt \
 --key-file=ksef.key \
 "--key-passphrase=MyPassword123!999999!" \
 --target-nip 0000000000
```

Output:
```
{"referenceNumber": "XXXXXXXX-XX-XXXXXXXXXX-XXXXXXXXXX-XX", "authenticationToken": {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "validUntil": "2026-02-08T14:02:26.6382248+00:00"}}
```

## Library usage
```python
from ksef_xades_auth import ksef_xades_auth, SubjectIdentifierType

with open("ksef.crt", "r") as f:
    cert_pem = f.read()

with open("ksef.key", "r") as f:
    key_pem = f.read()

res = ksef_xades_auth(
    api_base_url="https://api.ksef.mf.gov.pl/v2",
    cert_pem=cert_pem,
    key_pem=key_pem,
    key_passphrase=b"MyPassword123!999999!",
    target_nip="0000000000",
    identifier_type=SubjectIdentifierType.certificateSubject
)

print(res["authenticationToken"]["token"])
print(res["authenticationToken"]["validUntil"])
```
