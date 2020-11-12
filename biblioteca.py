import socket
import cripto
import server
import client
from threading import Thread
from networking import ClientNetworkConnection, ServerNetworkConnetion
from cryptography.hazmat.primitives import serialization
import json
from base64 import b64encode, b64decode


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

    def __init__(self, host, port, serverPublicKey, usersID=None, usersCredentials=None,  serverPrivateKey=None, clientPublicKey=None, clientPrivateKey=None):

        self.host = host
        self.port = port

        self.serverPublicKey = serverPublicKey

        if clientPublicKey is not None and clientPrivateKey is not None:
            self.client = client.VotingClient(
                clientPrivateKey=clientPrivateKey,
                clientPublicKey=clientPublicKey,
                serverPublicKey=serverPublicKey,
                clientPassword=None
            )

        else: 
            self.server = server.VotingServer(
                usersCredentials,
                usersID,
                serverPrivateKey,
                serverPublicKey,
                None,
                self.host,
                self.port
            )


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
    def checkOperator(self, conn):

        packet = conn.recv()
        print(packet.decode())

        operator = int(packet[0:2].decode())
        packet = packet[2:]

        print(f"Received Operation: {operator}")
        print(f"Received Packet: {packet[2:].decode()}")
        print(f"===" * 5)

        # Function checkSessionResult

        if (operator == 0): # Login Operation 
            message = self._handleLoginClient(conn, packet)

        elif(operator == 1):
            message = self.server.sendSessionResult(self, msg[:-1])
            conn.send(message)

        elif(operator == 2):
            print("teste1")

        elif(operator == 3):
            message = self.server.createVotingSession(self, packet) 
            conn.send(message)

        else:
            print("teste2")

        conn.close()
        


    """
        Will accept the connection request sent by user
    """
    def listenClients(self):

        # Create TCP/IP socket
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.bind((self.host, self.port))
        # s.setblocking(1) #Preventes timeout

        # Listen for incoming connections
        serverSocket.listen(4)

        while True:
            clientSocket, addr = serverSocket.accept()  # Returns a socket objetct and an address
            print(f'Accepted connection from {addr} ')
            
            conn = ServerNetworkConnetion(clientSocket)
            self.checkOperator(conn)
    

    """
        Log user in

        Args:
            login: String of user's login
            password: String of user's password 

        Returns:
            Authenticate a user
    """
    def makeLoginRequest(self, login, password):

        conn = ClientNetworkConnection(self.host, self.port)

        # Initiate login asking for challenge from server
        helloRequest = self.client.initiateLoginTransaction()
        conn.send(helloRequest)
        print(f"[LOGIN] Enviado request inicial: {helloRequest.decode()}")

        # Parse message containing server's challenge
        helloResponseAsBytes = conn.recv()
        print(f"[LOGIN] Recebido nonce desafio: {helloResponseAsBytes.decode()}")

        helloResponse = json.loads(helloResponseAsBytes)
        challengeNonce = b64decode(helloResponse['nonce'].encode())

        # Create Packet of User information to be authenticated
        loginRequestPacket, symKey = self.client.cryptCredentials(login, password, challengeNonce)
 
        # Send information to server and wait for response
        print(f'[LOGIN] - Sending login information')
        conn.send(loginRequestPacket)

        loginResponsePacket = conn.recv()
        print(f'[LOGIN] - Recebendo status da operacao: {loginResponsePacket}')

        conn.close()

        responseData = self.client.parseLoginResponse(loginResponsePacket, symKey)
        print(responseData)

        if not responseData['status'].lower() == 'ok':
            return False
        
        token = responseData['token'] 
        return token

    
    """
    """
    def _handleLoginClient(self, conn, packet):

        # Decrypt package (Initial Hello Request)
        jsonPack = json.loads(packet)
        print(packet.decode())

        # SEND CHALLENGE
        challengePacket = self.server.createChallengePacket()
        conn.send(challengePacket)
        print("[LOGIN] - Send Challenge Nonce")

        # RECEIVE CLIENTE REQUEST
        loginInfoPacket = conn.recv()
        loginResponse = self.server.checkRequestLogin(loginInfoPacket)

        conn.send(loginResponse)
        conn.close


    """
        Request the criation of a voting session

        Args:
            sessionId: A string
            candidates: A list of candidates (list of strings)
            sessionMode: A string "duration" or "maxVotes"
            maxVotes: An integer
            duration: An integer representing the minutes of duration
    """

    def createVotingSession(self, sessionId, candidates, sessionMode, maxVotes = 500, duration = 60):

        tagSize = 32

        con = ClientNetworkConnection(self.host, self.port)
        s = con.getConnection()

        message, hmacKey = client.createVotingSession(self.serverPublicKey, sessionId, candidates, sessionMode, maxVotes, duration)
        s.send(b"".join([message, 3]))
        
        byteAnswer = s.recv(1024)

        answer = byteAnswer.decode()
        
        tag = answer[-tagSize:]
        receivedSessionId = tag[:-tagSize]

        if not cripto.verifyTag(hmacKey, receivedSessionId.encode(), tag):
            print("Invalid tag")
            return "Error: Invalid Tag"

        return receivedSessionId
