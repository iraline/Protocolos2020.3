import unittest
from client import VotingClient
import cripto
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac


class VotingClientTest(unittest.TestCase):

    def setUp(self):

        self.client = self.loadVotingClient()

        # Client's Private Key
        with open('./tests/keys/client_test_keys.pem', 'rb') as clientPrivateKey: 
            self.clientPrivateKey = serialization.load_pem_private_key(clientPrivateKey.read(), password=None)

        # Client's Public Key
        with open('./tests/keys/client_test_keys.pub', 'rb') as clientPublicKey: 
            self.clientPublicKey = serialization.load_pem_public_key(clientPublicKey.read())
        
        # Client's Public Key
        with open('./tests/keys/server_test_keys.pem', 'rb') as serverPrivateKey: 
            self.serverPrivateKey = serialization.load_pem_private_key(serverPrivateKey.read(), password=None)
        
    # Read Client's Private and Public Keys and Server's public key to load VotingClient
    def loadVotingClient(self):

        with open('./tests/keys/client_test_keys.pem', 'rb') as privateKey: 
            with open('./tests/keys/client_test_keys.pub', 'rb') as publicKey: 
                with open('./tests/keys/server_test_keys.pub', 'rb') as serverPublicKey: 
                    return VotingClient(privateKey.read(), publicKey.read(), serverPublicKey.read())


    # Test: VotingClient.signMessage
    def test_can_sign_messages(self):

        message = b"Tocando um modao de arrastar o chifre no asfalto"
        signature = self.client.signMessage(message)

        isCorrectlySigned = True
        try:
            self.clientPublicKey.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

        except InvalidSignature:
            isCorrectlySigned = False

        self.assertTrue(isCorrectlySigned)

    # Test: VotingClient.verifySession
    def test_can_request_a_session_verification(self):

        sessionID = 'mySessionID'
        request, _ , _ = self.client.verifySession(sessionID)

        # Parse Packet
        encrypetedMacKeyLength = 512
        tagLength = 32
        nonceLength = 16

        encryptedMacKey = request[-encrypetedMacKeyLength:]
        request = request[:-encrypetedMacKeyLength]

        tag = request[-tagLength:]
        request = request[:-tagLength]

        message =  request
        nonce = message[:nonceLength]

        macKey = cripto.decryptWithPrivateKey(self.serverPrivateKey, encryptedMacKey)

        # Test if it's correctly tagged
        self.assertTrue(cripto.verifyTag(macKey, message, tag))

        # Test if it generates different nonces
        request2 = self.client.verifySession(sessionID)
        nonce2 = request2[:nonceLength]

        self.assertNotEqual(nonce, nonce2)


    # Test: VotingClient.createVotingSession
    def test_can_make_a_create_session_request(self):

        sessionName = 'Decidir o formato da Terra'
        candidates = ['bola', 'pizza']
        sessionMode = 'maxVotes'
        maxVotes = 1

        requestPacket = self.client.createVotingSession(
            sessionName,
            candidates,
            sessionMode,
            maxVotes=maxVotes
        )

        keyLength = 512
        tagLength = 32

        encryptedKey = requestPacket[-keyLength:]
        tag = requestPacket[-(keyLength + tagLength):-keyLength]
        message = requestPacket[:-(keyLength + tagLength)]

        hmacKey = cripto.decryptWithPrivateKey(self.serverPrivateKey, encryptedKey)
        self.assertTrue(cripto.verifyTag(hmacKey, message, tag))

