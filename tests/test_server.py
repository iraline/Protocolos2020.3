import unittest
from server import VotingServer
from cryptography.hazmat.primitives import hashes, hmac

class VotingServerTest(unittest.TestCase):

    def setUp(self):
        self.server = VotingServer('chavePrivada', 'chavePublica')

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
    

if __name__ == '__main__':
    unittest.main()