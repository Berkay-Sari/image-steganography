import socket
import sys
import hashlib
import magic
from diffie_hellman import DiffieHellman as DH
from rsa_signer import RSA_Signer as SignUtil
from AES import AES
from img_stego import ImageSteganographyUtil as Stego

host = '127.0.0.1'
port = 12345

p = 2**512+11
g = 5

bob = DH(p, g)
signer = SignUtil()

connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.connect((host, port))
print("[+] Connected to", (host, port))

alice_sign_public_key = connection.recv(4096)
print('[+] Alice\'s public sign key recieved.')

connection.sendall(signer.get_public_key_bytes())
print('[+] Public sign key sent to Alice.')

alice_public_key = DH.unserialize(connection.recv(4096))
print('[+] Recieved g^a (mod P)')

pk = DH.serialize(bob.public_key)
connection.sendall(pk)
print('[+] Sent g^b (mod P)')

# Calculate the shared secret
shared_secret_b = bob.generate_shared_secret(alice_public_key)

alice_sign = connection.recv(4096)
print('[+] Alice\'s signature recieved')

# Authentication using RSA
hashed_secret = hashlib.sha256(shared_secret_b).digest()
verified = SignUtil.verify_signature(hashed_secret, alice_sign, alice_sign_public_key)

if not verified:
    print('[-] Man in the middle attack detected connection closing...')
    connection.close()
    sys.exit()

print('[+] User Alice has been authenticated.')
signature = signer.sign_message(hashed_secret)
connection.sendall(signature)
print('[+] Signature sent to Alice.')

aes = AES(shared_secret_b)
print('[+] AES modul generated with shared secret')

key_len = int.from_bytes(connection.recv(4), byteorder='big')
print('[+] Aes key length for this session is selected as', key_len)
print('[+] Waiting for Alice...')

image_data = b""
data = connection.recv(1024)
while data:
    image_data += data
    data = connection.recv(1024)

print('[+] Steganographic image recieved.')
received_image_filename = './bob_data/' + input('Enter the name for the received image file (no need extension):')
image_extension = ".png"    
received_image_filename += image_extension

with open(received_image_filename, 'wb') as file:
    file.write(image_data)

print(f"[+] Image received and saved as {received_image_filename} successfully.")
cipher_hash_hex = Stego.extract_data(received_image_filename)
cipher_hash = bytes.fromhex(cipher_hash_hex)
hash = cipher_hash[-32:]
cipher = cipher_hash[:-32]
hash_code = hashlib.sha256(cipher).digest()
if not hash == hash_code:
    print('[-] Data is corrupted. integrity not achieved!')
    print('[INFO] Closing connection due to suspicious image.')
    connection.close()
    sys.exit()
decrypted_data = aes.decrypt_data(cipher, key_len)
mime = magic.Magic()
data_type = str(mime.from_buffer(decrypted_data))
print(f"[+] Decrypted data type: {data_type}")

file_extension = ".bin"
if "text" in data_type:
    file_extension = ".txt"
elif "JPEG" in data_type:
    file_extension = ".jpeg"
elif "PNG" in data_type:
    file_extension = ".png"
elif "PDF" in data_type:
    file_extension = ".pdf"
elif "kbps" in data_type: 
    file_extension = ".mp3"
    
file_path = './bob_data/' + input(f'Where do we write the secret data? (e.g secret{file_extension}): ')
if 'text' in data_type:
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(decrypted_data.decode('utf-8'))
else:
    with open(file_path, 'wb') as file:
        file.write(decrypted_data)

print(f"[+] Decrypted data has been written to {file_path}")

connection.close()