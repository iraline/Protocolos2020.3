import unittest
from server import VotingServer
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

class VotingServerTest(unittest.TestCase):

    def setUp(self):

        # Server's Public Key
        with open('./tests/keys/server_test_keys.pub', 'rb') as publicKey: 
            self.serverPublicKey = serialization.load_pem_public_key(publicKey.read())
        
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


    def test_if_integry_verification_works(self):

        message = b"Good bye, Cruel World!"
        hmacKey = b'S3cr3t'

        # Creating HMAC Tag
        h = hmac.HMAC(hmacKey, hashes.SHA256())
        h.update(message)
        hmacTag = h.finalize()

        # Verify function
        self.assertTrue(self.server.verifyPacketIntegrity(hmacKey, message, hmacTag))

        tampered_message = b"Good bye, Cruel World" # Without '!'
        self.assertFalse(self.server.verifyPacketIntegrity(hmacKey, tampered_message, hmacTag))


    # Just checks if nonce is not the same  
    def test_it_generates_different_nonces(self):
        
        nonce1 = self.server.generateNonce()
        nonce2 = self.server.generateNonce()

        self.assertNotEqual(nonce1, nonce2)


if __name__ == '__main__':
    unittest.main()