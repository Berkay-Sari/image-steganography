from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class AES:
    def __init__(self, shared_secret, info=b'Derive AES Keys'):
        self.shared_secret = shared_secret
        self.info = info

    def derive_key(self, key_length):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length // 8,
            salt=None,
            info=self.info,
            backend=default_backend()
        )

        key_material = hkdf.derive(self.shared_secret)
        print('[AES] Key derived successfully using the shared secret.')
        # print('[INFO] The Private key used in AES is', key_material)
        return key_material

    def encrypt_data(self, data, key_length):
        key_material = self.derive_key(key_length)

        cipher = Cipher(algorithms.AES(key_material), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        print('[AES] Data encrypted.')
        # print('[INFO] Encrypted data content is', ciphertext)
        return ciphertext

    def decrypt_data(self, ciphertext, key_length):
        key_material = self.derive_key(key_length)

        cipher = Cipher(algorithms.AES(key_material), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        # print('[AES] Data decrypted.')
        # print('[INFO] Decrypted data content is', decrypted_data)
        return decrypted_data


