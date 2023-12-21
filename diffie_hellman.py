from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
class DiffieHellman:
    def __init__(self, prime, generator):
        parameters = dh.DHParameterNumbers(prime, generator).parameters()
        self.private_key = parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def generate_shared_secret(self, other_public_key):
        shared_secret = self.private_key.exchange(
            other_public_key
        )
        # print('[INFO] Generated shared secret is', shared_secret)
        return shared_secret

    def serialize(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
    def unserialize(bytes):
        return serialization.load_pem_public_key(bytes, backend=default_backend())
