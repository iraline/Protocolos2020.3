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
        request = self.client.verifySession(sessionID)

        nonceLength = 48
        encrypetedMacKeyLength = 512
        tagLength = 32

        encryptedMacKey = request[-encrypetedMacKeyLength:]
        tag = request[-(encrypetedMacKeyLength + tagLength):-encrypetedMacKeyLength]
        message =  request[:-(encrypetedMacKeyLength + tagLength)]
        nonce = request[:nonceLength]

        macKey = cripto.decryptPacketWithPrivateKey(self.serverPrivateKey, encryptedMacKey)

        # Test if it's correctly tagged
        self.assertTrue(cripto.verifyTag(macKey, message, tag))

        # Test if it generates different nonces
        request2 = self.client.verifySession(sessionID)
        nonce2 = request2[:nonceLength]

        self.assertNotEqual(nonce, nonce2)
