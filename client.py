import os
import cripto
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography import exceptions
from exceptions import InvalidPacket
from VotingSession import VotingSession
from networking import ClientNetworkConnection

"""
        Request a verification for a session result

        Args:
            The session ID
        Returns:
            The packet that should be sent in bytearray format
    """

def verifySession(self, sessionId):

    nonce = cripto.generateNonce()
    message = b"".join([nonce, sessionId.encode()])
    macKey = cripto.generateMACKey()
    tag = cripto.createTag(macKey, message)
    message = b"".join([message, tag])
    encryptedMacKey = cripto.encryptWithPublicKey(
        self.serverPublicKey, macKey)
    message = b"".join([message, encryptedMacKey])
    return message, nonce, macKey


"""
    Recieve session result packet

    Args:
        The packet sent from the server method "server.sendSessionResult()"
        The nonce used in "client.verifySession()"
        The HMACKey used in "client.verifySession()"
    Returns:
        First value (status):

            An integer code signaling the status of the method that can be

            -1 if a security error ocurred
                0 if the session isn't finished
                1 if the session is over

        Second value:

            if status == -1: A string signaling an error
            if status ==  0: A string signaling an error
            if status ==  1: A session object
"""

def receiveSessionResult(packet, lastNonce, HMACKey):

    errorSz = 5
    nonceSz = 16
    tagSz = 32
    invalidTagSz = len("Invalid tag")

    securityErrorCode = -1
    unfinishedSessionCode = 0
    finishedSessionCode = 1

    try:
        anErrorOccur = packet[:errorSz].decode() == "ERROR"
    except:
        anErrorOccur = False

    if anErrorOccur:

        nonce = packet[errorSz:(errorSz + nonceSz)]

        if nonce != lastNonce:
            return securityErrorCode, "The packet that the server sent is invalid"

        else:
            if cripto.verifyTag(HMACKey, packet[:-tagSz], packet[-tagSz:]):
                if packet[(errorSz + nonceSz):(errorSz + nonceSz + invalidTagSz)] == "Invalid Tag":
                    return securityErrorCode, "The last packet that you sent to server is invalid"
                else:
                    return unfinishedSessionCode, "This session is still not finished"
            else:
                return securityErrorCode, "The packet that the server sent is invalid"

    else:

        nonce = packet[:nonceSz]
        byteDumpedSession = packet[nonceSz:-tagSz]
        tag = packet[-tagSz:]

        if nonce != lastNonce:
            raise InvalidPacket

        else:
            if cripto.verifyTag(HMACKey, b"".join([nonce, byteDumpedSession]), tag):

                sessionDict = json.loads(byteDumpedSession.decode())

                # Now, we have to convert the sessionDict to an object session

                requestedSession = VotingSession(
                    sessionName=sessionDict["id"],
                    candidates=sessionDict["candidates"],
                    sessionMode=sessionDict["sessionMode"],
                    duration=sessionDict["duration"],
                    maxVotes=sessionDict["maxVotes"],
                    candidatesFormat="Dictionary"
                )

                return finishedSessionCode, requestedSession

            else:
                return securityErrorCode, "The packet that the server sent is invalid"


class VotingClient:

    """
        Initialize Voting Client with client's private and public keys, alogn with server's public key

        Args:
            privateKey: A bytearray of a PEM File containing the client's private key
            publicKey: A bytearray of a PEM File containing the client's public key
            serverPublicKey: A bytearray of a PEM File containing the server's public key
            password: A bytearray of the optional password that may have been used to encrypt the private key
            Token: Should be a b64 or hex or a string. It will be assigned later.
    """

    def __init__(self, clientPrivateKey, clientPublicKey, serverPublicKey, clientPassword=None, host='localhost', port=9595):

        self.privateKey = serialization.load_pem_private_key(
            clientPrivateKey, password=clientPassword)
        self.publicKey = serialization.load_pem_public_key(clientPublicKey)
        self.serverPublicKey = serialization.load_pem_public_key(
            serverPublicKey)
        self.token = None

        self.serverHost = host
        self.serverPort = port
        self.token = None

    """
        Sign message with Client's Private Key

        Args:
            message: message to be signed

        Returns:
            Message Signature
    """

    def signMessage(self, message):
        return cripto.signMessage(self.privateKey, message)


    """
        Create a new voting session

        Args:
            sessionName: Session Unique identifier as a string
            candidates: List of strings containing candidates names.
            sessionMode: String that describes how this session will end. Either 'maxVotes' or 'duration'.
            maxVotes: An integer representing votes needed to end session. Used if sessionMode equals 'maxVotes'.
            duration: An integer representing time duration of the session in minutes. Used if sessionMode equals 'duration'.

        Returns:
            Packet containing a request for creating a new session.
    """

    def createVotingSession(self, sessionName, candidates, sessionMode, maxVotes=500, duration=60):

        sessionInfo = {
            'sessionName': sessionName,
            'candidates': candidates,
            'sessionMode': sessionMode
        }

        if sessionMode.lower() == 'maxvotes':
            sessionInfo['maxVotes'] = maxVotes
        elif sessionMode.lower() == 'duration':
            sessionInfo['duration'] = duration
        else:
            raise ValueError(
                'Invalid value for \'sessionMode\'. Choose one of \'maxVotes\' or \'duration\'.')

        # Creating Packet
        sessionInfoAsBytes = json.dumps(sessionInfo).encode()
        hmacKey = cripto.generateMACKey()
        tag = cripto.createTag(hmacKey, sessionInfoAsBytes)
        encryptedHMACKey = cripto.encryptWithPublicKey(
            self.serverPublicKey, hmacKey)

        return b''.join([sessionInfoAsBytes, tag, encryptedHMACKey])

    """
        Encrypt the login and password from the user with a symetric key.
        The symetric key is encrypted with the server`s publickey

        Args:
            self: Get the server's publicKey
            login: User's login
            password User's password
            nonce: nonce received from server
        Returns:
            The packet that should be sent in bytearray format
    """

    def cryptCredentials(self, login, password, nonce):

        symetricKey = cripto.generateSymmetricKey()

        message = {}
        message['login'] = login
        message['password'] = password

        json_data = json.dumps(message)

        encryptedMessage = cripto.encryptMessageWithKeyAES(
            symetricKey, 
            nonce, 
            json_data.encode()
        )

        encryptedKey = cripto.encryptWithPublicKey(
            self.serverPublicKey, 
            symetricKey
        )

        pack = {}
        pack['encryptedMessage'] = b64encode(encryptedMessage).decode()
        pack['encryptedKey'] = b64encode(encryptedKey).decode()
        pack['nonce'] = b64encode(nonce).decode()

        packet = json.dumps(pack).encode()

        return packet, symetricKey


    """
        Make initial request for login

        Return: 
            Packet for initiating login operation
    """
    def initiateLoginTransaction(self):

        # Send Hello Message
        initialRequest = {
            'op': 'hello'
        }        

        return b'00' + json.dumps(initialRequest).encode()


    """
        Parse Response packet send by server

        Args:
            packet: Server response due to user authentication final step
            symmetricKey: Key agreed to cipher communication

        Returns:
            Server response of login operation as JSON Object
    """
    def parseLoginResponse(self, packet, symmetricKey):

        packetData = json.loads(packet)

        nonce = b64decode(packetData['nonce'].encode())
        encryptedMessage = b64decode(packetData['encryptedMessage'].encode())

        messageAsBytes = cripto.decryptMessageWithKeyAES(
            symmetricKey,
            nonce,
            encryptedMessage
        )

        messageData = json.loads(messageAsBytes)

        # Decrypt data
        signedDigest = b64decode(messageData['signedDigest'].encode())
        digest = b64decode(messageData['digest'].encode())
        statusMessageAsBytes = b64decode(messageData['message'].encode())

        # Verify integrity and authentication
        if not cripto.verifySignature(self.serverPublicKey, digest, signedDigest):
            return False

        if not cripto.verifyDigest(statusMessageAsBytes, digest):
            return False

        statusMessage = json.loads(statusMessageAsBytes)
        return statusMessage


    """
        Log user in

        Args:
            login: String of user's login
            password: String of user's password 

        Returns:
            Authenticate a user
    """
    def handleLoginRequest(self, login, password):

        conn = ClientNetworkConnection(self.serverHost, self.serverPort)

        # Initiate login asking for challenge from server
        helloRequest = self.initiateLoginTransaction()
        conn.send(helloRequest)
        print(f"[LOGIN] Enviado request inicial: {helloRequest.decode()}")

        # Parse message containing server's challenge
        helloResponseAsBytes = conn.recv()
        print(f"[LOGIN] Recebido nonce desafio: {helloResponseAsBytes.decode()}")


        helloResponse = json.loads(helloResponseAsBytes)
        challengeNonce = b64decode(helloResponse['nonce'].encode())

        # Create Packet of User information to be authenticated
        loginRequestPacket, symKey = self.cryptCredentials(login, password, challengeNonce)

        # Send information to server and wait for response
        print(f'[LOGIN] - Sending login information')
        conn.send(loginRequestPacket)
        
        loginResponsePacket = conn.recv()
        print(f'[LOGIN] - Recebendo status da operacao: {loginResponsePacket}')

        conn.close()

        responseData = self.parseLoginResponse(loginResponsePacket, symKey)
        print(responseData)

        if not responseData['status'].lower() == 'ok':
            return False
        
        self.token = responseData['token'] 

        return True
        

    """
        Encrypt the "id_client" with a symetric key, sign this message with your private key
        and send a generate MasterKey encrypted with the server's public key

        Args:
            self: Get the server's publicKey and client's privateKey
            id_client: User's uniqueidentification.
        Returns:
            The packet that should be sent in bytearray format
    """

    def requestRegister(self, id_client):

        nonce = cripto.generateNonce()
        msKey = cripto.generateMasterKey()

        signId = cripto.signMessage(self.privateKey, id_client)

        symmetricHmac = cripto.generateKeysWithMS(msKey, nonce)

        symmetricKey = symmetricHmac[0]

        message = {}
        message['message'] = id_client  # bytes(id_client, encoding= 'utf-8')
        message['hashMessage'] = signId  # bytes(signId, encoding= 'utf-8')
        json_messageEncrypted = json.dumps(message)

        encryptedMessage = cripto.encryptMessageWithKeyAES(
            symmetricKey, nonce, json_messageEncrypted)
        criptedMsKey = cripto.encryptWithPublicKey(self.serverPublicKey, msKey)

        pack = {}
        pack['encryptedMessage'] = encryptedMessage
        pack['encryptedKey'] = criptedMsKey
        pack['nonce'] = nonce

        return json.dumps(pack)


    """
        Create a vote request to vote in a session 

        Args:
            sessionID: Session Identifier, a string.
            candidate: The canditate that the user chose, a string.

        Retruns:
            A byte array of the packet to be sent to the server
    """

    def createVoteRequest(self, sessionID, candidate):

        if self.token == None:
            print("ERROR! Your token shouldn't be None! Please login before vote.")
            return

        votingInfo = {
            'sessionID': sessionID,
            'vote': candidate,
            'token': self.token,
        }
        votingInfoAsBytes = json.dumps(votingInfo).encode()

        symKey = cripto.generateSymmetricKey()
        encryptedKey = cripto.encryptWithPublicKey(
            self.serverPublicKey,
            symKey
        )

        nonce = cripto.generateNonce()
        digest = cripto.createDigest(votingInfoAsBytes)
        # signedDigest = cripto.signMessage(self.privateKey, digest)

        packet = {
            'votingInfo': votingInfoAsBytes,
            'digest': digest,
            # 'signedDigest': signedDigest            
        }

        encryptedPacket = cripto.encryptMessageWithKeyAES(
            symKey,
            nonce,
            json.dumps(packet).encode()
        )

        packet = {
            'encryptedPacket': b64encode(encryptedPacket).decode(),
            'encryptedKey': b64encode(encryptedKey).decode(),
            'nonce': b64encode(nonce).decode(),
        }

        return json.dumps(packet).encode()
    

    """
        Handles the process of voting in a session
    """

    def handleVoteRequest(self, sessionId, candidate):

        packet = self.createVoteRequest(sessionId, candidate)
