from socket import *
import Crypto.Random.random as r
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad , unpad
p = 2582249878086908589655919172003011874329705792829223512830659356540647622016841194629645353280137831435903171972747559779
g = 2
#AES functions 
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

# Diffi hellman Exchange Functions 
def calc_client_private_key():
	return r.getrandbits(400)

def calc_client_public_key(client_private_key):
	return pow(g,client_private_key,p)

def calc_shared_key(server_public_key,client_priavte_key):
	return pow(server_public_key,client_private_key,p)
server_name='127.0.0.1'
server_port=55000
client_socket=socket(AF_INET,SOCK_STREAM)
client_socket.connect((server_name,server_port))
#generate client private key and calculate client public key
client_private_key=calc_client_private_key()
client_public_key=calc_client_public_key(client_private_key)
        
# Receive server's public key
server_public_key = int(client_socket.recv(2048).decode())

# Send client's public key to server
client_socket.send(str(client_public_key).encode())



# Compute shared secret
shared_secret = calc_shared_key(server_public_key, client_private_key)
hashed_secret = SHA256.new(str(shared_secret).encode()).digest()
print(f"SK Shared Key: {hashed_secret.hex()}")
while True:
	####################################################
	# Client sending a message
	message = input("Client: ")
	encrypted_msg = encrypt_message(message, hashed_secret) 
	final_message = encrypted_msg + compute_tag(encrypted_msg)
	client_socket.send(final_message)

	if message.lower() == "quit":
		print("Closing connection as requested.")
		client_socket.close()
		break

	# Client receiving a message
	encrypted_data = client_socket.recv(2048)
	if not encrypted_data:
		print("No data received. Closing connection.")
		client_socket.close()
		break

	encrypted_message, received_tag = encrypted_data[:-32], encrypted_data[-32:]

	
	if compute_tag(encrypted_message) == received_tag:
		decrypted_message = decrypt_message(encrypted_message, hashed_secret)
		if decrypted_message == "quit":
			print("Server requested to close the connection.")
			client_socket.close()
			break
		print(f"\nServer (decrypted message): {decrypted_message}")
		print(f"Server Cipher text(C): {encrypted_message}")
		print(f"Server Tag (tag): {received_tag}\n")
	else:
		print("Message integrity check failed. Closing connection.")
		client_socket.close()
		break



