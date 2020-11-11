import socket

#Create TCP/IP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = 'localhost'
port = 1234

try:
    # Bind the socket to the port
    variavel = (host, port)
    s.bind(variavel)
except socket.error as e:
    print(e)
    exit(0)

# Listen for incoming connections
s.listen(1)

# Wait for a connection
conn, addr = s.accept()
while True:
     # Receive the data with max b"1024
    data = conn.recv(1024)
    print("Received data: ", data.decode())
    conn.send(data)
