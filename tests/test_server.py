import unittest
from server import VotingServer
from VotingSession import VotingSession
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import cripto
from exceptions import InvalidPacket
import binascii
import bcrypt

class VotingServerTest(unittest.TestCase):

    def setUp(self):

        # Server's Public Key
        with open('./tests/keys/server_test_keys.pub', 'rb') as publicKey: 
            self.serverPublicKey = serialization.load_pem_public_key(publicKey.read())

        # Client's Private Key
        with open('./tests/keys/client_test_keys.pem', 'rb') as clientPrivateKey: 
            self.clientPrivateKey = serialization.load_pem_private_key(clientPrivateKey.read(), password=None)

        # Client's Public Key
        with open('./tests/keys/client_test_keys.pub', 'rb') as clientPublicKey: 
            self.clientPublicKey = serialization.load_pem_public_key(clientPublicKey.read())
        
        self.server = self.loadVotingServer()


    # Read Server's Private and Public Keys to load VotingServer
    def loadVotingServer(self):
        
        usersPubKeys = 'usersPubKeys.json'
        usersInfoStorage = None
       
        with open('./tests/keys/server_test_keys.pem', 'rb') as privateKey: 
            with open('./tests/keys/server_test_keys.pub', 'rb') as publicKey: 
                return VotingServer(
                    usersPubKeys, 
                    usersInfoStorage,
                    privateKey.read(), 
                    publicKey.read()
                )


    def test_can_decrypt_packet_encrypted_with_server_public_key(self):

        # Encrypt message with server's Public Key
        message = b"I love poodles"
        cipherText = self.serverPublicKey.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        serverResponse = self.server.decryptPacketWithServerPrivateKey(cipherText)
        self.assertEqual(message, serverResponse)

    def test_can_create_voting_session(self):

        # Create packet for Voting Session creation
        sessionOptions = {
            'sessionName': 'Pizza',
            'candidates': ['Portuguesa', 'Calabresa', 'Carne de Sol'],
            'sessionMode': 'maxVotes',
            'maxVotes': 10,
        }

        sessionJSON = json.dumps(sessionOptions)
        
        sessionAsBytes = sessionJSON.encode() 
        hmacKey = cripto.generateMACKey()

        encryptedHMACKey = cripto.encryptWithPublicKey(self.serverPublicKey, hmacKey)
        hmacTag = cripto.createTag(hmacKey, sessionJSON)

        packet = sessionAsBytes + hmacTag + encryptedHMACKey

        # Check Packet Parsing
        self.assertEqual(encryptedHMACKey, packet[-len(encryptedHMACKey):])
        self.assertEqual(hmacTag, packet[-(len(encryptedHMACKey) + len(hmacKey)):-len(encryptedHMACKey)])
        self.assertEqual(sessionAsBytes, packet[:-(len(encryptedHMACKey) + len(hmacKey))])

        # Session is created and stored in memory
        self.assertEqual(len(self.server.sessions), 0)
        sessionID = self.server.createVotingSession(packet)
        self.assertEqual(len(self.server.sessions), 1)
        self.assertEqual(sessionID, sessionOptions['sessionName'])

        # Server will reject creating new session with same ID
        with self.assertRaises(InvalidPacket):
            self.server.createVotingSession(packet) 


    def test_can_correctly_handle_a_voting_request(self):

        # Create Session
        pizzaSession = VotingSession(
            sessionName='pizza',
            candidates=['Calabresa', 'Mussarela'],
            sessionMode='maxVotes',
            maxVotes=20
        )

        userID = 'gabriel'
        authToken = "lalala"
        self.server.sessions['pizza'] = pizzaSession
        self.server.usersSessions[authToken] = userID

        # Create Voting Request
        votingInfo = {
            'sessionID': 'pizza',
            'vote': 'Calabresa',
            'token': authToken
        }
        votingInfoAsBytes = json.dumps(votingInfo).encode()
        digest = cripto.createDigest(votingInfoAsBytes)
        
        symKey = cripto.generateSymmetricKey()
        nonce = cripto.generateNonce()
        encryptedMessage = cripto.encryptMessageWithKeyAES(symKey, nonce, votingInfoAsBytes + digest)
        
        encryptedKey = cripto.encryptWithPublicKey(self.serverPublicKey, symKey)

        packet = b"".join([encryptedMessage, nonce, encryptedKey])

        # Send packet to server
        response = self.server.computeVoteRequest(packet)



    # Test: Server.checkRequestRegister
    def test_can_handle_a_register_request(self):

        userID = 'gabriel'

        with open('./keys/gabriel.pem', 'rb') as userPrivKeyFile:
            userPrivateKey = serialization.load_pem_private_key(
                userPrivKeyFile.read(),
                password=None
            ) 
            
        # Encrypt Packet
        masterKey = cripto.generateMasterKey()
        salt = cripto.generateSalt()
        symKey, hmacKey = cripto.generateKeysWithMS(masterKey, salt)

        hmacTag = cripto.createTag(hmacKey, userID)
        signedTag = cripto.signMessage(userPrivateKey, hmacTag)
        nonce = cripto.generateNonce()

        encryptedMasterKey = cripto.encryptWithPublicKey(self.serverPublicKey, masterKey)
        
        message = {
            'userID': userID,
            'hashMessage': signedTag.hex(),
        }

        messageAsBytes= json.dumps(message).encode()
        encryptedMessage = cripto.encryptMessageWithKeyAES(symKey, nonce, messageAsBytes)

        registerInfo = {
            'encryptedMessage': encryptedMessage.hex(),
            'encryptedKey': encryptedMasterKey.hex(),
            'nonce': nonce.hex(),
            'salt': salt.hex(),
        }

        request = json.dumps(registerInfo).encode()

        # Checking server response
        response = self.server.checkRequestRegister(request)
        responseJSON = json.loads(response)

        encryptedMessage = binascii.unhexlify(responseJSON['encryptedMessage'])
        nonce = binascii.unhexlify(responseJSON['nonce'])
        tag = binascii.unhexlify(responseJSON['tag'])

        message = cripto.decryptMessageWithKeyAES(
            symKey,
            nonce,
            encryptedMessage
        )

        messageJSON = json.loads(message)
        self.assertTrue(messageJSON['status'])

    

    def test_can_verify_a_user_password_correctly(self):

        password = b'132457'
        passwordHash = bcrypt.hashpw(password, bcrypt.gensalt())

        self.assertTrue(self.server.verifyUserPassword(password, passwordHash))


    def test_can_handle_a_login_request_correctly(self):

        # Add a user
        username = userID = 'gabriel' 
        userPassword = '123457'
        userObj = self.server.createUser(unittest, username, userPassword)

        self.server.users.append(userObj)

        # Creating a login packet
        symKey = cripto.generateSymmetricKey()
        nonce = cripto.generateNonce()

        encryptedKey = cripto.encryptWithPublicKey(
            self.serverPublicKey,
            symKey
        )

        message = {
            'login': username,
            'password': userPassword
        }

        encryptedMessage = cripto.encryptMessageWithKeyAES(
            symKey,
            nonce,
            json.dumps(message).encode()
        )

        packet = {
            'encryptedMessage': encryptedMessage.hex(),
            'encryptedKey': encryptedKey.hex(),
            'nonce': nonce.hex(),
        }

        packetJSONStr = json.dumps(packet) 

        # 'Send' Packet to server
        response = self.server.checkRequestLogin(packetJSONStr) 

        # Verifying server's response
        # Decrypt and deserialize
        decryptedResponse = cripto.decryptMessageWithKeyAES(
            symKey,
            nonce,
            response
        )

        responseData = json.loads(decryptedResponse)

        statusInfo = json.loads(responseData['message'])
        self.assertEqual(statusInfo['status'], 'Sucesso')
        self.assertTrue(self.server.validateToken(statusInfo['authToken']))
        

        