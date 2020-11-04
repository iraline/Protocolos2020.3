import unittest
from server import VotingServer
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import cripto
from exceptions import InvalidPacket

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
        with open('./tests/keys/server_test_keys.pem', 'rb') as privateKey: 
            with open('./tests/keys/server_test_keys.pub', 'rb') as publicKey: 
                return VotingServer(privateKey.read(), publicKey.read())


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

