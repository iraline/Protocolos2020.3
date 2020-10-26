from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography import exceptions
import os


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
        
        return self.privateKey.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    """
        Apply a message authentication code to a message using a key. To create the tag
        we are using the SHA256 Hash function.
        Args:
            key: A byte string
            message: A common string
        Returns:
            Message with a MAC in the end
    """

    def applyMAC(self, key, message):
        h = hmac.HMAC(key, hashes.SHA256())
        messageAsBytes = str.encode(message)
        h.update(messageAsBytes)
        return b"".join([messageAsBytes, h.finalize()])  # to get the message with the MAC appended
        # return h.finalize()                                #to get only the MAC

    """
        Verify if a message's MAC is valid, given a pre-shared key. To create the tag
        we are using the SHA256 Hash function.
        Args:
            key: A byte string
            message: A byte string
            sentMAC: A byte string
        Returns:
            It returns True if the MAC is valid or False if it isn't
    """


    def verifyMAC(self, key, sentMessage, sentMAC):
        h = hmac.HMAC(key, hashes.SHA256())
        messageAsBytes = str.encode(sentMessage)
        h.update(messageAsBytes)
        try:
            h.verify(sentMAC)
            return True
        except exceptions.InvalidSignature as err:
            return False

    """
        Generate a random master key of 256 bits.
        Args:
            None
        Returns:
            It returns a master key in byte format
    """

    def getMasterKey(self):
        return os.urandom(256)
