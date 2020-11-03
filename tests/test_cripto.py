import unittest
import cripto
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CriptTest(unittest.TestCase):

    def setUp(self):

        # Server's Private Key
        with open('./tests/keys/server_test_keys.pem', 'rb') as privateKey: 
            self.serverPrivateKey = serialization.load_pem_private_key(privateKey.read(), password=None)

        # Server's Public Key
        with open('./tests/keys/server_test_keys.pub', 'rb') as publicKey: 
            self.serverPublicKey = serialization.load_pem_public_key(publicKey.read())

        # Client's Private Key
        with open('./tests/keys/client_test_keys.pem', 'rb') as clientPrivateKey: 
            self.clientPrivateKey = serialization.load_pem_private_key(clientPrivateKey.read(), password=None)

        # Client's Public Key
        with open('./tests/keys/client_test_keys.pub', 'rb') as clientPublicKey: 
            self.clientPublicKey = serialization.load_pem_public_key(clientPublicKey.read())
        

    def test_it_generates_different_nonces(self):
        
        nonce1 = cripto.generateNonce()
        nonce2 = cripto.generateNonce()

        self.assertNotEqual(nonce1, nonce2)


    # Test: VotingClient.applyMAC
    def test_can_apply_mac_correctly(self):

        message = "Fui hackeado, chama a tempest!"
        key = b'S3cr3t'

        tag = cripto.createTag(key, message)
        
        # Verify
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message.encode())

        try:
            h.verify(tag)
            isVerificationSuccesful = True
        except InvalidSignature:
            isVerificationSuccesful = False

        self.assertTrue(isVerificationSuccesful)


    def test_if_integry_verification_works(self):

        message = b"Good bye, Cruel World!"
        hmacKey = b'S3cr3t'

        # Creating HMAC Tag
        h = hmac.HMAC(hmacKey, hashes.SHA256())
        h.update(message)
        hmacTag = h.finalize()

        # Verify function
        self.assertTrue(cripto.verifyTag(hmacKey, message, hmacTag))

        tampered_message = b"Good bye, Cruel World" # Without '!'
        self.assertFalse(cripto.verifyTag(hmacKey, tampered_message, hmacTag))


    def test_can_decrypt_with_symmetric_key(self):
        
        message = b"Dead man tells no tales"
        
        # Generate Nonce and Key
        nonce = cripto.generateNonce()
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)

        # Encrypt message
        cipherText = aesgcm.encrypt(nonce, message, associated_data=None)

        self.assertEqual(message, cripto.decryptPacketWithSymmetricKey(key, nonce, cipherText))


    def test_can_encrypt_message_with_public_key(self):

        message = b"Aqui nois constroi cifra, nao eh agua com base64"
        key = b'S3cr3t'

        cipherText = cripto.encryptWithPublicKey(self.clientPublicKey, message)

        decryptedText = self.clientPrivateKey.decrypt(
            cipherText, 
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        self.assertEqual(message, decryptedText)




    def test_can_decrypt_message_encrypted_with_public_key(self):

        # Encrypt message with Public Key
        message = b"I love poodles"
        cipherText = self.serverPublicKey.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        serverResponse = cripto.decryptPacketWithPrivateKey(self.serverPrivateKey, cipherText)
        self.assertEqual(message, serverResponse)


    def test_can_verify_signatures(self):
        
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
        with open('./tests/keys/client_test_keys.pub', 'rb') as clientPubKey: 
            self.assertTrue(cripto.verifySignature(clientPubKey.read(), message, signature))

        # Test signature using Server's public key
        # Could be any other key, just to tell the signature function works correctly.
        with open('./tests/keys/server_test_keys.pub', 'rb') as serverPubKey: 
            self.assertFalse(cripto.verifySignature(serverPubKey.read(), message, signature))

    
    # Test: generateMasterKey
    def test_generate_master_key_correctly(self):

        masterKey = cripto.generateMasterKey()

        # It must be 32 bytes (256-bit) long
        self.assertEqual(len(masterKey), 32)

        # It must genereate different masterKeys on different calls
        masterKey2 = cripto.generateMasterKey()
        self.assertNotEqual(masterKey, masterKey2)