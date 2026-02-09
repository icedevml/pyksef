class PEMPrivateKey:
    key_pem: bytes
    passphrase: bytes | None

    def __init__(self, key_pem: bytes, passphrase: bytes | None):
        self.key_pem = key_pem
        self.passphrase = passphrase
