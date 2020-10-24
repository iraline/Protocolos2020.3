from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

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

        The padding part is extracted from an example in Cryptography's Docs
        OAEP padding is the recommended choice for new protocols/applications.

        Args:
            packet -> Encrypted packet to be decrypted 

        Returns:
            Decrypted message
    """
    def decryptPacketWithServerPrivateKey(self, packet):
        
        return self.privateKey.decrypt(
            packet, 
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


    """
        Verifies if a received packet has integrity

        Args:
            msg: A bytearray or string of the packet being asserted
            tag: A bytearray or string of the HMAC tag sent, that will be verified.
            hmacKey: The authentication key used to process the HMAC 

        Returns:
            A boolean that that represents a succesful verification
    """
    def verifyPacketIntegrity(self, hmacKey, packet, hmacTag):

        hasIntegrity = True

        # Converts string to bytearray
        if isinstance(packet, str):
            packet = packet.encode() 

        if isinstance(hmacKey, str):
            hmacKey = hmacKey.encode() 
        
        # These functions expect a bytearray for key, packet and tag
        h = hmac.HMAC(hmacKey, hashes.SHA256()) 
        h.update(packet) 
        
        try:
            h.verify(hmacTag)
        except InvalidSignature:
            hasIntegrity = False

        return hasIntegrity



