from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature 

class VotingServer: 

    def __init__(self, privateKey, publicKey):

        self.privateKey = privateKey
        self.publicKey = publicKey


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



