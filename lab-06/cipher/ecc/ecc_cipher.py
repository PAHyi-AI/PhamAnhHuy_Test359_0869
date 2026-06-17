import os
from ecdsa import SigningKey, VerifyingKey, NIST256p, BadSignatureError

KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")

class ECCCipher:
    def __init__(self):
        os.makedirs(KEYS_DIR, exist_ok=True)
        self.signing_key = None
        self.verifying_key = None

    def generate_keys(self):
        self.signing_key = SigningKey.generate(curve=NIST256p)
        self.verifying_key = self.signing_key.get_verifying_key()
        # Save keys as PEM
        with open(os.path.join(KEYS_DIR, "private.pem"), "wb") as f:
            f.write(self.signing_key.to_pem())
        with open(os.path.join(KEYS_DIR, "public.pem"), "wb") as f:
            f.write(self.verifying_key.to_pem())

    def load_keys(self):
        priv_path = os.path.join(KEYS_DIR, "private.pem")
        pub_path = os.path.join(KEYS_DIR, "public.pem")
        if os.path.exists(priv_path) and os.path.exists(pub_path):
            with open(priv_path, "rb") as f:
                self.signing_key = SigningKey.from_pem(f.read())
            with open(pub_path, "rb") as f:
                self.verifying_key = VerifyingKey.from_pem(f.read())
            return True
        return False

    def sign(self, message: str) -> bytes:
        if self.signing_key is None:
            raise ValueError("Signing key not loaded. Generate or load keys first.")
        return self.signing_key.sign(message.encode("utf-8"))

    def verify(self, message: str, signature: bytes) -> bool:
        if self.verifying_key is None:
            raise ValueError("Verifying key not loaded.")
        try:
            return self.verifying_key.verify(signature, message.encode("utf-8"))
        except BadSignatureError:
            return False
