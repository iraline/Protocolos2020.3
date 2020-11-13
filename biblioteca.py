import socket
import cripto
import server
import client
from threading import Thread
from networking import ClientNetworkConnection, ServerNetworkConnetion
from cryptography.hazmat.primitives import serialization
import json
from base64 import b64encode, b64decode
import _thread


class Biblioteca():

    """
        Checks the result of a session

        Args:
            (String)host: Host's name
            (Int)port: Port to connect to the server
            (Dictionary)usersID: User's id_client and public key.
            (Array)usersCredentials: User's login, password and id_client .
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
            String with result, a list of candidates (if the session is not over yet) or an error message.
    """

    def checkSessionResult(self, id_session):

        conn = ClientNetworkConnection(self.host, self.port)

        # Prepare the package to be sent
        message, nonce, macKey = client.verifySession(
            id_session, self.serverPublicKey)

        # Concatenate operator
        message = b"".join([b"01", message])

        # Sends the message to the server
        conn.send(message)

        # Recieve the message from the server
        answer = conn.recv()

        # Treat the session result
        number, answer = client.receiveSessionResult(answer, nonce, macKey)

        return answer

    """
        Checks the received operator and forwards to the correct route to the server
        be able to handle with the current packet.

        Args:
            (Socket Object)conn: Object with the connection to client.

        Returns:
            Nothing
    """

    def checkOperator(self, conn):

        packet = conn.recv()
        # print(packet.decode())

        operator = int(packet[0:2].decode())
        packet = packet[2:]

        print(f"Received Operation: {operator}")
        # print(f"Received Packet: {packet[2:].decode()}")
        print(f"===" * 5)

        # Function checkSessionResult

        if (operator == 0):  # Login Operation
            self._handleLoginClient(conn, packet)

        elif(operator == 1):  # Check Session Result

            message = packet[0:-48]

            # Get the session result
            message = self.server.sendSessionResult(packet)

            conn.send(message)

        elif(operator == 2):
            self._handleRegisterRequest(conn, packet)

        elif(operator == 3):
            message = self.server.createVotingSession(packet)
            conn.send(message)

        elif(operator == 4):
            message = self.server.handleVotingRequestPacket(packet)
            conn.send(message)

        else:
            print("teste2")

        conn.close()
        _thread.exit()  # Finish thread

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
            # Returns a socket objetct and an address
            clientSocket, addr = serverSocket.accept()
            print(f'Accepted connection from {addr} ')

            conn = ServerNetworkConnetion(clientSocket)
            _thread.start_new_thread(
                self.checkOperator, (conn,))  # Create a new thread

    ##############
    ### LOGIN ####
    ##############

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
        print(
            f"[LOGIN] Recebido nonce desafio: {helloResponseAsBytes.decode()}")

        helloResponse = json.loads(helloResponseAsBytes)
        challengeNonce = b64decode(helloResponse['nonce'].encode())

        # Create Packet of User information to be authenticated
        loginRequestPacket, symKey = self.client.cryptLoginCredentials(
            login, password, challengeNonce)

        # Send information to server and wait for response
        print(f'[LOGIN] - Sending login information')
        conn.send(loginRequestPacket)

        loginResponsePacket = conn.recv()

        conn.close()

        responseData = self.client.parseLoginResponse(loginResponsePacket, symKey)

        if not responseData['status'].lower() == 'ok':
            return False

        token = responseData['token']

        self.client.token = token

        return token

    """
        Function for the server to handle the login flux

        Args:
            conn: Connection established with the client
            packet: Initial packet sent by client of the login flux

        Returns:
            Logs a user in if authentication was succesfull
    """

    def _handleLoginClient(self, conn, packet):

        # Decrypt package (Initial Hello Request)
        # jsonPack = json.loads(packet)

        # SEND CHALLENGE
        challengePacket = self.server.createChallengePacket()
        conn.send(challengePacket)
        print("[LOGIN] - Send Challenge Nonce")

        # RECEIVE CLIENTE REQUEST
        loginInfoPacket = conn.recv()
        loginResponse = self.server.checkRequestLogin(loginInfoPacket)

        conn.send(loginResponse)
        conn.close()

    """
        Request the criation of a voting session

        Args:
            sessionId: A string
            candidates: A list of candidates (list of strings)
            sessionMode: A string "duration" or "maxVotes"
            quantity: An integer representing the minutes of duration ou the maximum votes
    """

    def createVotingSession(self, sessionId, candidates, sessionMode, quantity):

        tagSize = 32

        conn = ClientNetworkConnection(self.host, self.port)

        message, hmacKey = client.createVotingSession(
            self.serverPublicKey, sessionId, candidates, sessionMode, quantity)
        conn.send(b"".join([b"03", message]))

        byteAnswer = conn.recv()

        tag = byteAnswer[-tagSize:]
        receivedSessionId = byteAnswer[:-tagSize].decode()

        if not cripto.verifyTag(hmacKey, receivedSessionId.encode(), tag):
            print("Invalid tag")
            return "Error: Invalid Tag"

        return receivedSessionId

    """
        Make vote session flux, from the client perspective

        Args:
            vote: 'Candidate' 
            sessionId: The name of the session
        Returns:
            True if the vote has been computed, else it returns false.
    """

    def sendVoteSession(self, vote, sessionId):

        con = ClientNetworkConnection(self.host, self.port)

        voteRequest, symKey, nonce = self.client.createVoteRequest(
            sessionId, vote)
        con.send(b"".join([b"04", voteRequest]))

        encryptedByteAnswer = con.recv()
        nonceForEncryption = encryptedByteAnswer[:16]
        encryptedByteAnswer = encryptedByteAnswer[16:]

        byteAnswer = cripto.decryptMessageWithKeyAES(
            symKey, nonceForEncryption, encryptedByteAnswer)

        status = byteAnswer[:4]
        receivedNonce = byteAnswer[4:20]
        signedHash = byteAnswer[20:]

        serverPublicKey = serialization.load_pem_public_key(
            self.serverPublicKey)

        if receivedNonce != nonce:
            print("Invalid nonce")
            return False

        if not cripto.verifySignature(serverPublicKey, cripto.createDigest(byteAnswer[:20]), signedHash):
            print("Invalid tag")
            return False

        else:
            if status.decode() == "fail":
                print("Your vote was not computed")
                return False

            else:
                print("Your vote has been computed")
                return True

    ##################
    #### REGISTER ####
    ##################


    """
          Register a new user in the system. Checks if id_client is valid to register. If sucess, return 1.
          Args:
              userId: id_client in a String format
              login: User's login in a String format
              password: User's password in a String format
    """

    def makeRegisterRequest(self, userID, login, password):

        conn = ClientNetworkConnection(self.host, self.port)

        # Packet with register information
        operationCode = b'02'
        initialRegisterPacket, symKey, hmacKey = self.client.createClientIDRegisterPacket(
            userID)
        conn.send(operationCode + initialRegisterPacket)

        statusResponsePacket = conn.recv()
        status = self.client.checkRegisterStatusResponse(
            statusResponsePacket,
            symKey,
            hmacKey
        )

        if not status:
            return status

        # Send user registration information
        registerInfoPacket = self.client.cryptRegisterCredentials(
            login, password, symKey, hmacKey)
        conn.send(registerInfoPacket)

        statusResponsePacket = conn.recv()
        status = self.client.checkRegisterStatusResponse(
            statusResponsePacket,
            symKey,
            hmacKey
        )

        return status

    """
        Is used only for the 'biblioteca.py'.     
    """

    def _handleRegisterRequest(self, conn, packet):

        # Receive User ID Packet
        userID, symKey, hmacKey = self.server.parseClientIDRegisterRequest(
            packet)

        # Verify if id is usable
        status = 'ok'
        if not self.server.getUserPublicKey(userID):
            status = 'invalido'

        statusPacket = self.server.createStatusPacket(status, symKey, hmacKey)
        conn.send(statusPacket)
        print("[REGISTER] - Send Status Packet")

        # Get User Info (Login and Password)
        registerInfoPacket = conn.recv()
        status = self.server.checkClientInfoRegisterRequest(
            userID, registerInfoPacket, symKey, hmacKey)

        statusPacket = self.server.createStatusPacket(status, symKey, hmacKey)
        conn.send(statusPacket)
