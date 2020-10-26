import unittest
from server import VotingServer
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

    
    def test_can_decrypt_with_symmetric_key(self):
        
        message = b"Dead man tells no tales"
        
        # Generate Nonce and Key
        nonce = self.server.generateNonce()
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)

        # Encrypt message
        cipherText = aesgcm.encrypt(nonce, message, associated_data=None)

        self.assertEqual(message, self.server.decryptPacketWithSymmetricKey(key, nonce, cipherText))


    def test_it_generates_different_nonces(self):
        
        nonce1 = self.server.generateNonce()
        nonce2 = self.server.generateNonce()

        self.assertNotEqual(nonce1, nonce2)

    
    def test_can_verify_client_signatures(self):
        
        message = b"Hey, listen"
        signature = self.clientPrivateKey.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Test signature using Client's public key
        with open('./tests/keys/client_test_keys.pub', 'rb') as clientPublicKey: 
            self.assertTrue(self.server.verifyClientSignature(clientPublicKey.read(), message, signature))

        # Test signature using Server's public key
        # Could be any other key, just to tell the signature function works correctly.
        with open('./tests/keys/server_test_keys.pub', 'rb') as serverPublicKey: 
            self.assertFalse(self.server.verifyClientSignature(serverPublicKey.read(), message, signature))



if __name__ == '__main__':
    unittest.main()