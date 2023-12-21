import socket
import sys
import hashlib
from diffie_hellman import DiffieHellman as DH
from rsa_signer import RSA_Signer as SignUtil
from AES import AES
from img_stego import ImageSteganographyUtil as Stego

host = '127.0.0.1'
port = 12345

p = 2**512+11
g = 5

alice = DH(p, g)
signer = SignUtil()

alice_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
alice_socket.bind((host, port))
alice_socket.listen()
connection, bob = alice_socket.accept()
print('[+] Connection from', bob)

connection.sendall(signer.get_public_key_bytes())
print('[+] Public sign key sent to Bob')

bob_public_sign_key = connection.recv(4096)
print('[+] Bob\'s public sign key recieved')

pk = DH.serialize(alice.public_key)
connection.sendall(pk)
print('[+] Sent g^a (mod P)')

bob_public_key = DH.unserialize(connection.recv(4096))
print('[+] Recieved g^b (mod P)')

# Calculate the shared secret
shared_secret_a = alice.generate_shared_secret(bob_public_key)

# Authentication using RSA
hashed_secret = hashlib.sha256(shared_secret_a).digest()
signature = signer.sign_message(hashed_secret)
connection.sendall(signature)
print('[+] Signature sent to Bob.')
bob_sign = connection.recv(4096)
verified = SignUtil.verify_signature(hashed_secret, bob_sign, bob_public_sign_key)
if not verified:
    print('[-] Man in the middle attack detected connection closing...')
    connection.close()
    sys.exit()

print('[+] User Bob has been authenticated.')
aes = AES(shared_secret_a)
print('[+] AES modul generated with shared secret')

# Send key length
# The longer the safer but the slower
while True:
    try:
        key_len = int(input('Choose the key length for AES[128 - 192 - 256]: '))
        if key_len in [128, 192, 256]:
            break  
        else:
            print('[-] Invalid input. Please enter 128, 192, or 256.')
    except ValueError:
        print('[-] Invalid input. Please enter a valid integer.')

byte_format = key_len.to_bytes(4, byteorder='big')
connection.sendall(byte_format)
print('[+] Aes key length for this session is selected as', key_len)

while True:
    data_path = './alice_data/' + input('Enter the name of the file that stores the secret data: ')

    try:
        with open(data_path, 'rb') as file:
            data = file.read()
        break  
    except FileNotFoundError:
        print(f"The file '{data_path}' does not exist. Please enter a valid file name.")

ciphertext = aes.encrypt_data(data, key_len)
cipher_hash = ciphertext + hashlib.sha256(ciphertext).digest()
new_img_path = Stego.insert_data(cipher_hash.hex())
with open(new_img_path, 'rb') as file:
    connection.sendfile(file)

print('[+] Steganographic image sent to Bob.')
connection.close()