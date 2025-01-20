import socket, ssl, sys, pprint

hostname = sys.argv[1] #client1-10.9.0.5) 
port = 4433
cadir = '/volumes/certC'        

# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

# TCP handshake
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))

# TLS handshake
ssock = context.wrap_socket(sock, server_hostname=hostname, do_handshake_on_connect=False)
ssock.do_handshake()   # Start the handshake

try:
    while True:
        # Get user input
        message = input("Enter message: ")
        # Send user input to server
        ssock.sendall(message.encode())

        # Read response from server
        response = ssock.recv(2048).decode()
        pprint.pprint("Response from server: {}".format(response))
except KeyboardInterrupt:
    print("\nClosing connection.")
finally:
    # Close the TLS Connection
    ssock.shutdown(socket.SHUT_RDWR)
    ssock.close()

