import secrets
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import cripto

class VotingServer: 


    """
        Initialize Voting server with its private and public keys 

        Args:
            privateKey: A bytearray of a PEM File containing the server's private key
            publicKey: A bytearray of a PEM File containing the server's public key
            password: A bytearray of the optional password that may have been used to encrypt the private key
    """
    def __init__(self, privateKey, publicKey, password=None):

        self.privateKey = serialization.load_pem_private_key(privateKey, password=password)
        self.publicKey = serialization.load_pem_public_key(publicKey)
 

    """
        Decrypt packets encrypted with the Server's Public Key

        Args:
            packet: Encrypted packet

        Returns:
            Decrypted packet
    """
    def decryptPacketWithServerPrivateKey(self, packet):
        return cripto.decryptPacketWithPrivateKey(self.privateKey, packet) 



