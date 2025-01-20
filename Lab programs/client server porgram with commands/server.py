



#import socket
#s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#s.bind((socket.gethostname(),9090))
#print(f" Server Listening socket: {s.getsockname()}")
#s.listen(1)

#while True:
#client_socket,client_addr=s.accept()
#print(f" Client request received")
#print(f"Server-Client {client_socket.getsockname()}")
#client_socket.send(bytes("Hello","utf-8"))

import socket
import time
import threading

def handle_client(client_socket, address):
    print(f"Accepted connection from {address}")

    client_socket.send(f"Connected to server. Your address: {address}\n".encode('utf-8'))

    client_socket.settimeout(15)

    try:
        while True:
            data = client_socket.recv(1024).decode('utf-8')

            if not data:
                break

            if data == "TIME":
                current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                client_socket.send(f"Current time: {current_time}\n".encode('utf-8'))
            elif data == "EXIT":
                break
            else:
                client_socket.send("Invalid command!\n".encode('utf-8'))

    except socket.timeout:
        print(f"Connection with {address} timed out")

    finally:
        print(f"Closing connection with {address}")
        client_socket.close()

# Create a TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a specific address and port
# host = '127.0.0.1'
host = socket.gethostname()
port = 12345
server_socket.bind((host, port))

# Listen for incoming connections
server_socket.listen(1)
print(f"Server listening on {host}:{port}")

while True:
    client_socket, address = server_socket.accept()
    client_handler = threading.Thread(target=handle_client, args=(client_socket, address))
    client_handler.start()
