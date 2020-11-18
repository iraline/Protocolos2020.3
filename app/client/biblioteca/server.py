import secrets
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from .exceptions import InvalidPacket
from . import cripto
import json
from .VotingSession import VotingSession
from cerberus import Validator
import os
import binascii
from base64 import b64encode, b64decode
import bcrypt
import socket
import threading
from .networking import ServerNetworkConnetion

class VotingServer:

    """
        Initialize Voting server with its private and public keys 

        Args:
            userPubKeys: Path to file containing JSON data about user's ids and their public keys
            privateKey: A bytearray of a PEM File containing the server's private key
            publicKey: A bytearray of a PEM File containing the server's public key
            password: A bytearray of the optional password that may have been used to encrypt the private key
    """

    def __init__(self, userPubKeys, usersInfoStorage, privateKey, publicKey, password=None, host='localhost', port=9595):

        self.privateKey = serialization.load_pem_private_key(
            privateKey, password=password)
        self.publicKey = serialization.load_pem_public_key(publicKey)
        self.sessions = {}

        # Load Registered User's Public Keys
        # Used only for registering users in the platform
        self.userPubKeys = self.loadUserPubKeys(userPubKeys)

        # Load Registered User
        self.users = self.loadUsersInfo(usersInfoStorage)

        # User Session AuthToken
        self.usersSessions = {}
        
        self.host = host
        self.port = port


    """
        Load JSON File containing user's ids and public keys

        Args:
            userPubKeysFilePath: Path to file contaning user's data as JSON

        Returns:
            Dictionary containing userID as key and Public Key as value. 
            {
                "iraline": b'PublickKey',
                ...
            }
    """
    def loadUserPubKeys(self, userPubKeysFilePath):
        
        if not os.path.exists(userPubKeysFilePath):
            raise ValueError("User Public Key file does not exist.")

        with open(userPubKeysFilePath, 'r') as file:
            userPubKeysJSON = json.load(file)

        # Transform PubKey String in bytes
        for userID, pubKey in userPubKeysJSON.items():
            userPubKeysJSON[userID] = pubKey.encode()

        return userPubKeysJSON


    """
        Load JSON file containing stored registerd users

        Args:
            userPubKeysFilePath: Path to file contaning user's data as JSON

        Returns:
            Dictionary as follows. 
            [
                {
                    id: "userID",
                    username: "soandso",
                    password: "bcrypted_password"
                }
            ]
    """
    def loadUsersInfo(self, userInfoFilePath):
        
        if not userInfoFilePath or not os.path.exists(userInfoFilePath):
            return []

        with open(userInfoFilePath, 'r') as file:
            userInfoJSON = json.load(file)
        
        return userInfoJSON


    """
        Register a new user to the platform

        Args:
            userID: User identifier that must be free for registering (Can't have two accounts for same user)
            username: Username chosen by the user
            password: User's password
    
        Returns:
            Create a new user 
    """
    def createUser(self, userID, username, password):

        newUser = {}
        newUser['id'] = userID
        newUser['username'] = username

        if isinstance(password, str):
            password = password.encode()

        hashedPassword = bcrypt.hashpw(password, salt=bcrypt.gensalt())
        newUser['password'] = hashedPassword

        for user in self.users:

            if userID == user['id']:
                return False
            
            if username == user['username']:
                return False 

        
        self.users.append(newUser)
        return True
        

    """
        Verify if password matches with user's password hash using the secure bcrypt method

        Args:
            password: Password sent 
            passwordHash: User's password hash

        Returns:
            Wheter password match or not
    """
    def verifyUserPassword(self, password, passwordHash):

        if isinstance(password, str):
            password = password.encode()

        if isinstance(passwordHash, str):
            passwordHash = passwordHash.encode()
        
        return bcrypt.hashpw(password, passwordHash) == passwordHash
    
    
    """
        Generate an authentication token associated with a user

        Args:
            userID: User Identifier

        Returns:
            Authentication token
    """
    def generateAuthToken(self, userID):

        authToken = os.urandom(48).hex()

        # Remove older tokens
        for token in list(self.usersSessions.keys()):
            if self.usersSessions[token] == userID:
                del self.usersSessions[token]

        self.usersSessions[authToken] = userID
        return authToken
    

    """
        Get User's Serialized Public Key

        Args:
            userID: User Identifier

        Returns:
            Crypography object of user's public key
    """
    def getUserPublicKey(self, userID):
        
        if userID not in self.userPubKeys:
            return None
            
        userPubKeyString = self.userPubKeys[userID]
        return serialization.load_pem_public_key(userPubKeyString)


    """
        Validate authToken

        Args:
            authToken: Authentication token that identifies a logged in user

        Returns:
            Wheter token is valid
    """
    def validateToken(self, authToken):
        return authToken in self.usersSessions.keys()


    """
        Decrypt packets encrypted with the Server's Public Key

        Args:
            packet: Encrypted packet

        Returns:
            Decrypted packet
    """

    def decryptPacketWithServerPrivateKey(self, packet):
        return cripto.decryptWithPrivateKey(self.privateKey, packet)

    """
        Create Voting session from packet request

        Args:
            packet: Packet received without OP field (operation) 
        
        Returns:
            A string representing the session Name (ID) of created voting session

        Raises:
            InvalidPacket
    """

    def createVotingSession(self, packet):

        # Parse packet
        # encryptedHMACKey has length of 512 bytes and is located at the end of the packet
        # hmacTAG is 32 bytes (256 bits)
        # message is the remaining content which has variable size

        keyLength = 512
        tagLength = 32

        encryptedHMACKey = packet[-keyLength:]
        hmacTag = packet[-(keyLength + tagLength):-keyLength]
        message = packet[:-(keyLength + tagLength)]

        hmacKey = self.decryptPacketWithServerPrivateKey(encryptedHMACKey)

        if not cripto.verifyTag(hmacKey, message, hmacTag):
            text = 'error-This tag is invalid'.encode()
            tag = cripto.createTag(hmacKey, text)
            message = b"".join([text, tag])
            return message

        # Get Session Options
        sessionInfo = json.loads(message.decode())

        # Check if session options sent make for a valid session
        if not self.validateVotingSessionOptions(sessionInfo):
            text = 'error-This session is invalid'.encode()
            tag = cripto.createTag(hmacKey, text)
            message = b"".join([text, tag])
            return message

        session = VotingSession(
            sessionName=sessionInfo['sessionName'],
            candidates=sessionInfo['candidates'],
            sessionMode=sessionInfo['sessionMode'],
            maxVotes=sessionInfo.get('maxVotes', None),
            duration=sessionInfo.get('duration', None)
        )

        # Add Session
        self.sessions[session.id] = session

        # Generating a tag to have integrity
        text = f'ok-{session.id}'.encode()
        tag = cripto.createTag(hmacKey, text)
        message = b"".join([text, tag])

        return message

    """
        Validate if packet contains valid information to create a new Voting Session.
        Also validate if sessionName can be used or is already taken.

        Args:
            sessionInfo: Packet info containing options for a new voting session. It is a dictionary

        Returns:
            Wheter packet information is valid or not. True if valid, else false.

    """

    def validateVotingSessionOptions(self, sessionInfo):

        # Create Session Packet
        schema = {
            'sessionName': {
                'type': 'string',
                'empty': False,
                'maxlength': 200,
                'required': True
            },
            'candidates': {
                'type': 'list',
                'empty': False,
                'schema': {'type': 'string'},
                'required': True,
                'maxlength': 999
            },
            'sessionMode': {
                'type': 'string',
                'allowed': ['maxVotes', 'duration'],
                'required': True
            },
            'maxVotes': {
                'type': 'number',
                'dependencies': {'sessionMode': 'maxVotes'},
                'min': 1,
                # 'required': True,
                'excludes': 'duration'
            },
            'duration': {
                'type': 'number',
                'dependencies': {'sessionMode': 'duration'},
                # 'required': True,
                'excludes': 'maxVotes'
            }
        }

        # Validate if packet sent got all fields correctly
        validator = Validator(schema)
        isPacketValid = validator.validate(sessionInfo)

        isSessionNameAvailalable = sessionInfo['sessionName'] not in self.sessions
        
        if not isPacketValid:
            print(sessionInfo)
            print(validator._errors)

        return isPacketValid and isSessionNameAvailalable


    """
        Verify if the tag sent from client from the verify session package is valid

        Args:
            The package sent from the client method "client.verifySession()"

        Returns:
            True if the tag is valid, else false, the nonce used, the sessionId and the mac key
    """

    def verifySessionTag(self, package):
        
        nonceSz = 16
        tagSz = 32
        encryptedMacKeySz = 512

        if len(package) <= (nonceSz + tagSz + encryptedMacKeySz):
            return False

        message = package[:-(encryptedMacKeySz + tagSz)]
        sentTag = package[-(encryptedMacKeySz + tagSz):-encryptedMacKeySz]
        sentEncryptedMacKey = package[-encryptedMacKeySz:]

        nonce = message[:nonceSz]
        sessionId = message[nonceSz:].decode()

        macKey = cripto.decryptWithPrivateKey(
            self.privateKey, sentEncryptedMacKey)

        if cripto.verifyTag(macKey, message, sentTag):
            return True, nonce, sessionId, macKey
        else:
            return False, nonce, sessionId, macKey


    """
    Returns session result if the end condition is true, else if it the session exists return the list of candidates.
    Else, it will return an error packet.

    Args:
        The packet sent from the client method "client.verifySession()"
    Retuns:
        A packet containing an error message or the session object
    """

    def sendSessionResult(self, packet):
        status, nonce, sessionId, macKey = self.verifySessionTag(packet)

        if status == False:
            # In this case we should return a packet signaling that the tag was invalid
            message = b"".join([b"ERROR", nonce])
            message = b"".join([message, b"Invalid tag"])
            InvalidTagPacket = "".join(
                [message, cripto.createTag(macKey, message)])
            return InvalidTagPacket

        elif not sessionId in self.sessions:
            # Therefore, we must send the packet signaling that the session isn't over yet
            message = b"".join([b"ERROR", nonce])
            message = b"".join([message, b"Not exists!"])
            invalidSessionPacket = b"".join(
                [message, cripto.createTag(macKey, message)])
            return invalidSessionPacket

        else:
            if self.sessions[sessionId].sessionMode.lower() == "maxvotes":
                # Hence, we must check if the maximum number of votes has been reached

                votes = self.sessions[sessionId].candidates.values()
                numVotes = sum(votes)

                if numVotes >= self.sessions[sessionId].maxVotes:
                    # Therefore, we must send the packet with the result

                    dumpedSession = json.dumps(
                        self.sessions[sessionId].__dict__
                    )
                    message = b"".join([nonce, dumpedSession.encode()])
                    tag = cripto.createTag(macKey, message)
                    sessionResultPacket = b"".join([message, tag])

                    return sessionResultPacket

                else:
                    # Therefore, we must send the packet signaling that the session isn't over yet
                    message = b"".join([b"ERROR", nonce])

                    auxList = []
                    i = 0
                    for candidate in self.sessions[sessionId].candidates:
                        auxList.append((candidate, i))
                        i += 1

                    dumpedList = json.dumps(auxList)
                    message = b"".join([message, b"UnfinishedS", dumpedList.encode()])
                    
                    UnfinishedSessionPacket = b"".join([message, cripto.createTag(macKey, message)])
                    return UnfinishedSessionPacket

            else:

                isSessionDurationOver = self.sessions[sessionId].hasFinished()

                if isSessionDurationOver:
                    # Therefore, we must send the packet with the result

                    dumpedSession = json.dumps(
                        self.sessions[sessionId].__dict__)
                    message = b"".join([nonce, dumpedSession.encode()])
                    tag = cripto.createTag(macKey, message)
                    sessionResultPacket = b"".join([message, tag])

                    return sessionResultPacket

                else:
                    # Therefore, we must send the packet signaling that the session isn't over yet
                    message = b"".join([b"ERROR", nonce])

                    auxList = []
                    candidateList = list(self.sessions[sessionId].candidates.keys())
                    for id, candidate in enumerate(candidateList):
                        auxList.append((candidate, id))

                    dumpedList = json.dumps(auxList)
                    message = b"".join([message, b"UnfinishedS", dumpedList.encode()])
                    
                    UnfinishedSessionPacket = b"".join(
                        [message, cripto.createTag(macKey, message)])
                    return UnfinishedSessionPacket

    """              
       Check if the id_client really exists in the system. If exist, it's allowed 
       to create an account in the system.
    
        Args:
            self: Get the server's privateKey and a list of possible clients 
            package: Package generate for the requestRegister

        Returns:
            The packet that should be sent in bytearray format
    """

    def checkClientInfoRegisterRequest(self, userID, package, symmetricKey, macTag):

        # Decrypt package
        jsonPack = json.loads(package)

        encryptedMessage = b64decode(jsonPack['encryptedMessage'].encode())
        nonce = b64decode(jsonPack['nonce'].encode())
        tag = b64decode(jsonPack['tag'].encode())

        if not cripto.verifyTag(macTag, encryptedMessage, tag):
            raise InvalidPacket("Failed to verify integrity")
        
        decryptedMessage = cripto.decryptMessageWithKeyAES(
            symmetricKey, 
            nonce, 
            encryptedMessage
        )

        message = json.loads(decryptedMessage)

        login = message['login']
        password = message['password']

        if len(login) < 8 or len(password) < 8:
            return 1, "Login ou senha menor que o tamanho minimo de 8 caracteres"

        return 0, self.createUser(userID, login, password)

    
    """
        Extract info from a Voting Request Packet

        Args:
            packet: packet sent by the client containing its vote.

        Return:
            Voting Info sent by client
    """
    
    def handleVotingRequestPacket(self, packet):
        packetAsDict = json.loads(packet.decode())
        
        nonce = b64decode(packetAsDict['nonce'].encode())
        encryptedKey = b64decode(packetAsDict['encryptedKey'].encode())
        encryptedPacket = b64decode(packetAsDict['encryptedPacket'].encode())


        keyLength = 512
        digestLength = 32
        nonceLength = 16

        if len(packet) <= keyLength + digestLength + nonceLength:
            raise InvalidPacket('Voting Request has length smaller than minimun possible packet')
    
        symKey = self.decryptPacketWithServerPrivateKey(encryptedKey)
        ByteJSONmessage = cripto.decryptMessageWithKeyAES(symKey, nonce, encryptedPacket)
        messageAsDict = json.loads(ByteJSONmessage.decode())

        digest = b64decode(messageAsDict['digest'].encode())
        votingInfoAsBytes = b64decode(messageAsDict['votingInfo'].encode())

        if not cripto.verifyDigest(votingInfoAsBytes, digest):
            raise InvalidPacket("Integrity verification failed")

        votingInfo = json.loads(votingInfoAsBytes.decode())

        nonceForEncryption = cripto.generateNonce()

        print(self.validateVotingInfo(votingInfo))
        if self.validateVotingInfo(votingInfo) and self.computeVoteRequest(votingInfo):
            
            print("Voto computado")
            succMsg = b"".join([b"succ", nonce])
            succMsgHash = cripto.createDigest(succMsg)
            signedSuccHash = cripto.signMessage(self.privateKey, succMsgHash)

            succMsg = b"".join([succMsg, signedSuccHash])
            succMsg = cripto.encryptMessageWithKeyAES(symKey, nonceForEncryption, succMsg)
            return b"".join([nonceForEncryption, succMsg])
            
        print("Voto nao computado")
        errorMsg = b"".join([b"fail", nonce])
        errorMsgHash = cripto.createDigest(errorMsg)
        signedErrorHash = cripto.signMessage(self.privateKey, errorMsgHash)

        errorMsg = b"".join([errorMsg, signedErrorHash])
        errorMsg = cripto.encryptMessageWithKeyAES(symKey, nonceForEncryption, errorMsg)
        return b"".join([nonceForEncryption, errorMsg])
        

    """
        Validates if sent Voting packet contains a valid format.
        It validates the token, the vote and the session ID.

        Args:
            votingInfo: Dictionary with voting information sent by client

        Returns:
            True if voting info is valid, else false
    """
    def validateVotingInfo(self, votingInfo):

        schema = {
            'sessionID': {'type': 'string', 'required': True},
            'vote': {'type': 'string', 'required': True, 'minlength': 3, 'maxlength': 3},
            'token': {'type': 'string', 'required': True}
        } 

        # Validate if packet sent got all fields correctly 
        validator = Validator(schema)
        
        isPacketValid = validator.validate(votingInfo)
        if not isPacketValid:
            print("Invalid Packet")
            return False

        session = self.sessions.get(votingInfo['sessionID'], None)
        if not session:
            print("Invalid Session")
            return False

        if not self.validateToken(votingInfo['token']):
            print("Invalid Token")
            return False

        return True


    """
        Validate and Compute Vote Request

        Args:
            packet: Voting Request packet sent by client

        Returns:
            Computes client vote in that session and returns wheter the computation was
            successful or not. So it also returns a boolen
    """
    def computeVoteRequest(self, votingInfo):
        
        if not self.validateVotingInfo(votingInfo):
            raise InvalidPacket
        
        session = self.sessions[votingInfo['sessionID']]
        userID = self.usersSessions[votingInfo['token']]

        hasSuccesfullyVoted = session.vote(userID, votingInfo['vote'])
        print(f"hasSuccesfullyVoted {hasSuccesfullyVoted}")
        return hasSuccesfullyVoted


    """              
       Check if the credentials sent is valid or not.
    
        Args:
            self: Get the server's privateKey  
            userList: Get the list with users and passwords in the system
            package: Json package generate for the cryptCredentials

        Returns:
            Encrypted json message package with status, authToken and nonce

    """
    def checkRequestLogin(self, package):

        jsonPack = json.loads(package)
        encryptedMessage = b64decode(jsonPack['encryptedMessage'].encode())
        encryptedKey = b64decode(jsonPack['encryptedKey'].encode())
        nonce = b64decode(jsonPack['nonce'].encode())
        
        symmetricKey = cripto.decryptWithPrivateKey(
            self.privateKey, 
            encryptedKey
        )
        
        decryptedMessage = cripto.decryptMessageWithKeyAES(
            symmetricKey, 
            nonce, 
            encryptedMessage
        )

        jsonMessage = json.loads(decryptedMessage)

        # Getting the parameters from  the message
        login = jsonMessage['login']
        password = jsonMessage['password']

        validUser = False

        # Check if the credentials are the same
        for user in self.users:
            if login == user['username'] and self.verifyUserPassword(password, user['password']):
                authToken = self.generateAuthToken(user['id'])
                validUser = True
                break
        
        message = {}

        if (validUser):
            message['status'] = "ok"
            message['token'] = authToken
        else:
            message['status'] = "Invalido"
        
        jsonMessage = json.dumps(message).encode()
        digest = cripto.createDigest(jsonMessage)
        signedDigest = cripto.signMessage(self.privateKey, digest)

        messagePreJson = {}
        messagePreJson['message'] = b64encode(jsonMessage).decode()
        messagePreJson['digest'] = b64encode(digest).decode()
        messagePreJson['signedDigest'] = b64encode(signedDigest).decode()
        messageJson = json.dumps(messagePreJson)

        serverNonce = cripto.generateNonce()

        confirmationPacket = cripto.encryptMessageWithKeyAES(
            symmetricKey, 
            serverNonce, 
            messageJson.encode()
        )

        responsePacket = {
            'nonce': b64encode(serverNonce).decode(),
            'encryptedMessage': b64encode(confirmationPacket).decode()
        }

        responsePacketAsBytes = json.dumps(responsePacket).encode()

        return responsePacketAsBytes


    """
        Server must send a challenge for the client to sign.
        This is done to avoid replay attacks could log a user in, 
        even though the attacker could not get the token

        Returns:
            Packet containing the nonce-challenge 

    """
    def createChallengePacket(self):

        challengeNonce = cripto.generateNonce()
        helloRespone = {
            'nonce': b64encode(challengeNonce).decode()
        }
        helloResponeAsBytes = json.dumps(helloRespone).encode()
        return helloResponeAsBytes


    
    """
        Parse packet containing user info (login, password) for registegin

        Args:
            packet: Packet containing the user ID and some fields for integrity check

        Returns:
            userID: User identifier
            symKey: Symmetric key used to encrypt communication
            hmacKey: Key for authentication and integrity
    """
    def parseClientIDRegisterRequest(self, packet):

        packetData = json.loads(packet)

        salt = b64decode(packetData['salt'].encode())
        nonce = b64decode(packetData['nonce'].encode())
        encryptedMasterKey = b64decode(packetData['encryptedKey'].encode())
        encryptedMessage = b64decode(packetData['encryptedMessage'].encode())

        masterKey = self.decryptPacketWithServerPrivateKey(encryptedMasterKey)

        symKey, hmacKey = cripto.generateKeysWithMS(masterKey, salt)

        messageAsBytes = cripto.decryptMessageWithKeyAES(
            symKey,
            nonce,
            encryptedMessage
        )

        message = json.loads(messageAsBytes)

        # Check integrity and signature
        signedDigest = b64decode(message['signedDigest'].encode())
        digest = b64decode(message['digest'].encode())
        userID = message['userID']

        data = {
            'status': 'ok',
            'symKey': symKey,
            'hmacKey': hmacKey,
        }

        if not self.getUserPublicKey(userID):
            data['status'] = 'invalido'
            data['statusText'] = 'User id was not physically registered'
            return data

        if not cripto.verifySignature(self.getUserPublicKey(userID), digest, signedDigest):
            data['status'] = 'invalido'
            data['statusText'] = 'User signature doesn\'t match'
            return data

        if not cripto.verifyDigest(userID, digest):
            data['status'] = 'invalido'
            data['statusText'] = 'Fail to verify integrity'
            return data
        
        if data['status'] == 'ok':
            data['userID'] = userID
            return data
        
        return data


    """
        Create a packet for returning the status of the operation
        
        Args:
            status: Wheter operation was succesful or not
            symKey: Symmetric key used to encrypt communication
            hmacKey: Key for authentication and integrity

        Returns:
            Packet with operation status
    """
    def createStatusPacket(self, status, symKey, hmacKey, statusText=None):
        
        if isinstance(status, bool):
            status = 'ok' if status else 'invalido'

        message = {
            'status': status
        } 

        if statusText is not None:
            message['statusText'] = statusText
        
        print(status)
        tag = cripto.createTag(hmacKey, status.encode())
        message['tag'] = b64encode(tag).decode()

        nonce = cripto.generateNonce()
        encryptedMessage = cripto.encryptMessageWithKeyAES(
            symKey,
            nonce,
            json.dumps(message).encode()
        )

        packet = {
            'encryptedMessage': b64encode(encryptedMessage).decode(),
            'nonce': b64encode(nonce).decode()
        }

        return json.dumps(packet).encode()

        