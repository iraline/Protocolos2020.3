from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography import exceptions
import os
import cripto


class VotingClient:

    """
        Initialize Voting Client with client's private and public keys, alogn with server's public key 

        Args:
            privateKey: A bytearray of a PEM File containing the client's private key
            publicKey: A bytearray of a PEM File containing the client's public key
            serverPublicKey: A bytearray of a PEM File containing the server's public key
            password: A bytearray of the optional password that may have been used to encrypt the private key
    """
    def __init__(self, clientPrivateKey, clientPublicKey, serverPublicKey, clientPassword=None):

        self.privateKey = serialization.load_pem_private_key(clientPrivateKey, password=clientPassword)
        self.publicKey = serialization.load_pem_public_key(clientPublicKey)
        self.serverPublicKey = serialization.load_pem_public_key(serverPublicKey)


    """
        Sign message with Client's Private Key

        Args:
            message: message to be signed

        Returns:
            Message Signature
    """
    def signMessage(self, message):
        return cripto.signMessage(self.privateKey, message)

    
    """
        Request a verification for a session result

        >CONSIDERING THE CASTING OF AN INTEGER TO A 4 BYTE BYTEARRAY<

        Args:
            The session ID
        Returns:
            The package that should be sent in bytearray format
    """
    def verifySession(self, sessionId):
        nonce = cripto.generateNonce()
        message = b"".join([nonce, sessionId.encode()])
        macKey = cripto.generateMACKey()
        tag = cripto.createTag(macKey, message)
        message = b"".join([message, tag])
        encryptedMacKey = cripto.encryptWithPublicKey(self.serverPublicKey, macKey)
        message = b"".join([message, encryptedMacKey])
        return message