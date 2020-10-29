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


    # Test: VotingClient.applyMAC
    def test_can_apply_mac_correctly(self):

        message = "Fui hackeado, chama a tempest!"
        key = b'S3cr3t'

        tag = cripto.applyMAC(key, message)
        
        # Verify
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message.encode())

        try:
            h.verify(tag)
            isVerificationSuccesful = True
        except InvalidSignature:
            isVerificationSuccesful = False

        self.assertTrue(isVerificationSuccesful)


    # Test: VotingClient.verifyMAC
    def test_can_verify_mac_correctly(self):
        
        message = b"Oh sheep, here we go again"
        key = b'S3cr3t'

        # Create HMAC
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message)
        tag = h.finalize()

        # Verify
        self.assertTrue(cripto.verifyMAC(key, message, tag))
