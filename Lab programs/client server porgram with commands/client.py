#! /usr/bin/python3

import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(), 12345))


msg = s.recv(1024)
print(msg.decode())

cmd = "TIME"
s.sendall(cmd.encode())
msg = s.recv(1024)
print(msg.decode())
cmd = "HELLO"
s.sendall(cmd.encode())
msg = s.recv(1024)
print(msg.decode())
cmd = "EXIT"
s.sendall(cmd.encode())
if not s.recv(1024):
    s.close()
s.close()


# time.sleep(20)

"""
cmd="TIME"
s.sendall(cmd.encode())
msg = s.recv(1024)
print(msg.decode())

cmd="HELLO"
s.sendall(cmd.encode())
msg = s.recv(1024)
print(msg.decode())



cmd="EXIT"
s.sendall(cmd.encode())
if not s.recv(1024):
       s.close()
"""
