'''import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = 'localhost'
port = 1234

# Connect the socket to the port where the server is listening
s.connect((host, port))

while True:
    # Send data
    data = input("Enter data: ")
    s.send(data.encode())
    ira = s.recv(1024)
    print(ira.decode())
'''

import biblioteca

biblioteca.connectToServer('localhost',1234)