import socket
from diffie_hellman import DiffieHellman 

host = '127.0.0.1'
port = 12345

p = 23
g = 5

alice = DiffieHellman(p, g)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen()
connection, client_address = server_socket.accept()
print("Connection from", client_address)

# Send public key to the Bob
connection.sendall(str(alice.public_key).encode())
print("Sent Alice's public key:", alice.public_key)

# Receive public key from the client
B_public_key = int(connection.recv(1024).decode())
print(f"Received Bob's public key: {B_public_key}")

# Calculate the shared secret
shared_secret_a = alice.generate_shared_secret(B_public_key)
print("Shared Secret Key:", shared_secret_a)

connection.close()
