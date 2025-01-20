from socket import *
import Crypto.Random.random as r
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
p = 2582249878086908589655919172003011874329705792829223512830659356540647622016841194629645353280137831435903171972747559779
g = 2
# AES Functions 
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes  # Prepend IV to ciphertext for use in decryption

def decrypt_message(ciphertext, key):
    iv = ciphertext[:AES.block_size]  # Extract IV from the beginning
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def compute_tag(ciphertext):
    hash_obj = SHA256.new(ciphertext)
    return hash_obj.digest()

# Diffi Hellman Key Exchange Functions 
def calc_server_private_key():
	return r.getrandbits(400)

def calc_server_public_key(server_private_key):
	return pow(g,server_private_key,p)

def calc_shared_key(client_public_key,server_priavte_key):
	return pow(client_public_key,server_private_key,p)

server_port=55000
welcome_socket=socket(AF_INET,SOCK_STREAM)
welcome_socket.bind(('',server_port))
welcome_socket.listen(1)
while True:
	connection_socket,addr=welcome_socket.accept()
	print(f"Connection established with {addr}")
	#generate server private key and calculate server public key
	server_private_key=calc_server_private_key()
	server_public_key=calc_server_public_key(server_private_key)
        # Send server's public key to client
	connection_socket.send(str(server_public_key).encode())
        # Receive client's public key
	client_public_key = int(connection_socket.recv(2048).decode())
        # Compute shared secret
	shared_secret = calc_shared_key(client_public_key, server_private_key)
	hashed_secret = SHA256.new(str(shared_secret).encode()).digest()
	print(f"SK Shared Key: {hashed_secret.hex()}")

	while True:
		#################################################
		# Server receiving a message
		#let us assume data sent is binary encoded
		encrypted_data = connection_socket.recv(2048)
		if not encrypted_data:
			print("No data received. Closing connection.")
			break

		# tag is appended at the end and is 32 bytes long
		encrypted_message, received_tag = encrypted_data[:-32], encrypted_data[-32:]

		
		if compute_tag(encrypted_message) == received_tag:
			decrypted_message = decrypt_message(encrypted_message, hashed_secret)
			if decrypted_message == "quit":
				print("Client requested to close the connection.")
				connection_socket.close()
				break
			print(f"\nClient (decrypted message): {decrypted_message}")
			print(f"Client Cipher Text (C): {encrypted_message}")
			print(f"Client Tag (tag): {received_tag}\n")
		else:
			print("Message integrity check failed. Closing connection.")
			connection_socket.close()
			break

		# Server sending a message
		#sent data is encoded
		message = input("Server: ")

		if message.lower() == "quit":
			connection_socket.send(encrypt_message(message.lower(), hashed_secret) + compute_tag("quit"))
			connection_socket.close()
			print("Closing connection as requested.")
			break
		encrypted_response = encrypt_message(message, hashed_secret)
		response_tag = compute_tag(encrypted_response)
		connection_socket.send(encrypted_response + response_tag)
	

