import socket
import cripto
import server
import client
from threading import Thread

from cryptography.hazmat.primitives import serialization

# Create TCP/IP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


class Biblioteca():

    """
        Checks the result of a session

        Args:
            (String)host: Host's name
            (Int)port: Port to connect to the server
            (Dictionary)usersID: User's id_client and public key.
            (Dictionary)usersCredentials: User's login and password .
            (Bytearray)serverPublicKey: Server's public key.
            (Bytearray)serverPrivateKey: Server's private key.

        Returns:
            Return the object.
    """

    def __init__(self, host, port, usersID, usersCredentials, serverPublicKey, serverPrivateKey):

        self.host = host
        self.port = port
        self.usersID = usersID
        self.usersCredentials = usersCredentials
        self.serverPrivateKey = serialization.load_pem_private_key(
            serverPrivateKey, None)
        self.serverPublicKey = serialization.load_pem_public_key(
            serverPublicKey)

    """
        Checks the result of a Session

        Args:
            (String)id_session: Session Unique identifier.

        Returns:
            String with result.
    """
    def checkSessionResult(self, id_session):

        # Tag for the server identify the route
        operator = b"1"

        # Connect the socket with host and port
        s.connect((self.host, self.port))

        # Prepare the package to be sent
        message = client.verifySession(self, id_session)
        message = b"".join([message, operator])

        # Sends the message to the server
        s.send(message)

        # Recieve the message from the server
        answer = s.recv(1024)

        return answer.decode()


    """
        Checks the received operator and forwards to the correct route.

        Args:
            (Socket Object)conn: Object with the connection to client.

        Returns:
    """
    def checkOperator(self, conn, cliente):

        msg = conn.recv(1024)
        operator = msg[-1]

        # Function checkSessionResult
        if(operator == 1):
            message = server.VotingServer.sendSessionResult(self, msg[:-1])
            conn.send(message)

        elif(operator == 2):
            print("teste1")

        else:
            print("teste2")

    """
        Will accept the connection request sent by user
    """
    def listenClients(self):

        try:
            # Bind the socket to the port
            access = (self.host, self.port)
            s.bind(access)
        except socket.error as e:
            print(e)
            exit(0)

        # Listen for incoming connections
        s.listen(20)

        while True:

            conn, addr = s.accept()  # Returns a socket objetct and an address
           
            s.setblocking(1) #Preventes timeout
            
        conn.close
