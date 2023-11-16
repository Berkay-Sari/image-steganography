import random

class DiffieHellman:
    def __init__(self, prime, generator):
        self.prime = prime
        self.generator = generator
        self.private_key = random.randint(2, prime - 2)  # private key should be kept secret
        self.public_key = pow(generator, self.private_key, prime)  # public key to share

    def generate_shared_secret(self, other_public_key):
        shared_secret = pow(other_public_key, self.private_key, self.prime)
        return shared_secret
    