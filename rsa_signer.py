from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

class RSA_Signer:
    def __init__(self):
        self.private_key, self.public_key = self.generate_key_pair()

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_message(self, message):
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print('[RSA] Signature generated.')
        # print('[INFO] Your signature is', signature)
        return signature

    @staticmethod
    def verify_signature(message, signature, public_key):
        public_key = RSA_Signer.get_pk_from_bytes(public_key)
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print('[RSA] Signature verified.')
            return True
        except Exception:
            print('[RSA] Signature not verified.')
            return False
        
    def get_public_key_bytes(self):
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # print('[INFO] Your public key is', public_key)
        return public_key_bytes
    
    @staticmethod
    def get_pk_from_bytes(public_key_bytes):
        public_key = serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )
        # print('[INFO] Using this public key for verifying', public_key)
        return public_key
