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

        conn = ClientNetworkConnection(self.host, self.port)
        
        print(id_session)

        # Prepare the package to be sent
        message,nonce,macKey = client.verifySession(id_session, self.serverPublicKey)

        # Concatenate operator
        message = b"".join([b"01",message])

        # Sends the message to the server
        conn.send(message)

        # Recieve the message from the server
        answer = conn.recv()
        
        #Treat the session result
        number, answer = client.receiveSessionResult(answer, nonce, macKey)  

        if number == -1:
            print(answer)
        elif number == 0:
            print(answer)

        return answer


    """
        Checks the received operator and forwards to the correct route.

        Args:
            (Socket Object)conn: Object with the connection to client.

        Returns:
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

        if (operator == 0): # Login Operation 
            self._handleLoginClient(conn, packet)

        elif(operator == 1): # Check Session Result

            message = packet[0:-48]
           
            #Get the session result
            message = self.server.sendSessionResult(packet)
   
            conn.send(message)

        elif(operator == 2):
            message = self._handleRegisterRequest(conn, packet)

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
            clientSocket, addr = serverSocket.accept()  # Returns a socket objetct and an address
            print(f'Accepted connection from {addr} ')
            
            conn = ServerNetworkConnetion(clientSocket)
            _thread.start_new_thread(self.checkOperator, (conn))  # Create a new thread

            self.checkOperator(conn)
    


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
        print(f"[LOGIN] Recebido nonce desafio: {helloResponseAsBytes.decode()}")

        helloResponse = json.loads(helloResponseAsBytes)
        challengeNonce = b64decode(helloResponse['nonce'].encode())

        # Create Packet of User information to be authenticated
        loginRequestPacket, symKey = self.client.cryptLoginCredentials(login, password, challengeNonce)
 
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
        conn.close()


    """
        Request the criation of a voting session

        Args:
            sessionId: A string
            candidates: A list of candidates (list of strings)
            sessionMode: A string "duration" or "maxVotes"
            maxVotes: An integer
            duration: An integer representing the minutes of duration
    """

    def createVotingSession(self, sessionId, candidates, sessionMode, quantity):

        tagSize = 32

        conn = ClientNetworkConnection(self.host, self.port)

        message, hmacKey = client.createVotingSession(self.serverPublicKey, sessionId, candidates, sessionMode, quantity)
        conn.send(b"".join([b"03", message]))
        
        byteAnswer = conn.recv()
        
        tag = byteAnswer[-tagSize:]
        receivedSessionId = byteAnswer[:-tagSize].decode()

        if not cripto.verifyTag(hmacKey, receivedSessionId.encode(), tag):
            print("Invalid tag")
            return "Error: Invalid Tag"

        return receivedSessionId


    def sendVoteSession(self, vote, sessionId):

        con = ClientNetworkConnection(self.host, self.port)
        s = con.getConnection()

        voteRequest, symKey, nonce = self.client.createVoteRequest(sessionId, vote)
        s.send(b"".join([b"04", voteRequest.encode()]))

        encryptedByteAnswer = s.recv(1024)

        # Deve receber um nonce, e uma assinatura do hash dele, encriptados.

        byteAnswer = cripto.decryptMessageWithKeyAES(symKey, nonce, encryptedByteAnswer)

        receivedNonce = byteAnswer[:16]
        signedHash = byteAnswer[16:]
        
        if receivedNonce != nonce:
            print("Invalid nonce")
            return False

        if not cripto.verifySignature(self.server.publicKey, cripto.createDigest(receivedNonce), signedHash):
            print("Invalid tag")
            return False
        
        else:
            print("Your vote has been computed")
            return True



    ##################
    #### REGISTER ####
    ##################

    """
    """
    def makeRegisterRequest(self, userID, login, password):

        conn = ClientNetworkConnection(self.host, self.port)

        # Packet with register information
        operationCode = b'02'
        initialRegisterPacket, symKey, hmacKey = self.client.createClientIDRegisterPacket(userID)
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
        registerInfoPacket = self.client.cryptRegisterCredentials(login, password, symKey, hmacKey)
        conn.send(registerInfoPacket)

        statusResponsePacket = conn.recv()
        status = self.client.checkRegisterStatusResponse(
            statusResponsePacket,
            symKey,
            hmacKey
        )

        return status


    """
    """
    def _handleRegisterRequest(self, conn, packet):

        # Receive User ID Packet
        userID, symKey, hmacKey = self.server.parseClientIDRegisterRequest(packet)

        # Verify if id is usable
        status = 'ok'
        if not self.server.getUserPublicKey(userID):
            status = 'invalido'
        
        statusPacket = self.server.createStatusPacket(status, symKey, hmacKey)
        conn.send(statusPacket)
        print("[REGISTER] - Send Status Packet")

        # Get User Info (Login and Password)
        registerInfoPacket = conn.recv()
        status = self.server.checkClientInfoRegisterRequest(userID, registerInfoPacket, symKey, hmacKey)

        print(self.server.users)
        statusPacket = self.server.createStatusPacket(status, symKey, hmacKey)
        conn.send(statusPacket)
