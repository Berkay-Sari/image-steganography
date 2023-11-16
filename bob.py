import socket
from diffie_hellman import DiffieHellman  

host = '127.0.0.1'
port = 12345

p = 23
g = 5

bob = DiffieHellman(p, g)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, port))
print(f"Connected to {host}:{port}")

# Receive Alice's public key
A_public_key = int(client_socket.recv(1024).decode())
print("Received A's public key:", A_public_key)

# Calculate the shared secret
shared_secret_b = bob.generate_shared_secret(A_public_key)

# Send Bob's public key to the Alice
client_socket.sendall(str(bob.public_key).encode())
print("Sent Bob's public key:", bob.public_key)

print("Shared Secret Key:", shared_secret_b)

# Close the client socket
client_socket.close()




