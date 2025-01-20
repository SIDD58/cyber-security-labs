import socket
import ssl
import pprint
from _thread import *

html = """
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html><html><body><h1>This is our COMP8677 Class!</h1></body></html>
"""

SERVER_CERT = '/volumes/certS/Test.crt'
SERVER_PRIVATE = '/volumes/certS/Test.key'

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain(SERVER_CERT, SERVER_PRIVATE)

serverPort = 4433
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serverSocket.bind(("", serverPort))
serverSocket.listen(5)

print("The server is ready to receive")

def multi_threaded_client(connectionSocket):
    try:
        ssock = context.wrap_socket(connectionSocket, server_side=True)
        print("TLS connection established")

        while True:
            # Receive message from client
            data = ssock.recv(1024).decode()
            if not data:
                break

            # Reverse the message
            reversed_data = data[::-1]

            # Send reversed message back to client
            ssock.sendall(reversed_data.encode())

        ssock.shutdown(socket.SHUT_RDWR)  # Close the TLS connection
        ssock.close()
    except Exception as e:
        print("TLS connection fails:", e)
    finally:
        connectionSocket.close()

while True:
    connectionSocket, addr = serverSocket.accept()
    print("TCP connect from:", addr)
    start_new_thread(multi_threaded_client, (connectionSocket,))

