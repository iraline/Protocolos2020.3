import secrets
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
            packet: Encrypted packet to be decrypted 

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
        Decrypt packet encrypted with given symmetric Key.
        It's expected for the packet to have been encrypted with AES256 and GCM mode

        Args:
            key: Symmetric key used in encryption
            nonce: Bytearray used as nonce. Never reuse the same (nonce, key) pair
            packet: Encrypted packet
        
        Returns:
            Decrypted packet
    """
    def decryptPacketWithSymmetricKey(self, key, nonce, packet):
        
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, packet, associated_data=None)


    """
        Verifies if a received packet has integrity

        Args:
            hmacKey: The authentication key used to process the HMAC 
            packet: A bytearray or string of the packet being asserted
            hmacTag: A bytearray or string of the HMAC tag sent, that will be verified.

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
        
        if isinstance(hmacTag, str):
            hmacTag = hmacTag.encode() 


        # These functions expect a bytearray for key, packet and tag
        h = hmac.HMAC(hmacKey, hashes.SHA256()) 
        h.update(packet) 
        
        try:
            h.verify(hmacTag)
        except InvalidSignature:
            hasIntegrity = False

        return hasIntegrity


    """
        Generate nonce

        Returns
            48-byte-long-random bytearray to be used as nonce
    """
    def generateNonce(self):
        return secrets.token_bytes(48)

    

    """
        Verify if the packet was signed with the provided Public Key

        Args:
            clientPublicKey: Bytearray of the Client's Public Key
            message: Message signed with corresponding Client's Private Key
            signature: Signature of the message
        
        Returns:
            Wheter it was signed by the corresponding Private Key or not.
    """
    def verifyClientSignature(self, clientPublicKey, message, signature):

        matchesSignature = True

        # Load Client's Public Key Object
        clientPublicKey = serialization.load_pem_public_key(clientPublicKey)

        try:
            clientPublicKey.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            matchesSignature = False

        return matchesSignature