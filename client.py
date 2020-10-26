
from cryptography.hazmat.primitives import serialization


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


    