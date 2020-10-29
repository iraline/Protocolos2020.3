import secrets
import os
import cripto
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


"""
    Generate nonce

    Returns
        48-byte-long-random bytearray to be used as nonce
"""
def generateNonce():
    return secrets.token_bytes(48)


"""
    Verifies if a received packet has integrity
    Args:
        hmacKey: The authentication key used to process the HMAC 
        packet: A bytearray or string of the packet being asserted
        hmacTag: A bytearray or string of the HMAC tag sent, that will be verified.
    Returns:
        A boolean that that represents a succesful verification
"""
def verifyPacketIntegrity(hmacKey, packet, hmacTag):
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
    Decrypt packet encrypted with given symmetric Key.
    It's expected for the packet to have been encrypted with AES256 and GCM mode
   
    Args:
        key: Symmetric key used in encryption
        nonce: Bytearray used as nonce. Never reuse the same (nonce, key) pair
        packet: Encrypted packet
    
    Returns:
        Decrypted packet
"""
def decryptPacketWithSymmetricKey(key, nonce, packet):
    return AESGCM(key).decrypt(nonce, packet, associated_data=None)


"""
    Decrypt packets encrypted with the Public Key schemes

    The padding part is extracted from an example in Cryptography's Docs
    OAEP padding is the recommended choice for new protocols/applications.
   
    Args:
        packet: Encrypted packet to be decrypted 
    
    Returns:
        Decrypted message
"""
def decryptPacketWithPrivateKey(privateKey, packet):
        
    return privateKey.decrypt(
        packet, 
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)


"""
    Verify if the packet was signed with the provided Public Key

    Args:
        publicKey: Bytearray of the Sender's Public Key
        message: Message signed with corresponding Sender's Private Key
        signature: Signature of the message
    
    Returns:
        Wheter it was signed by the corresponding Private Key or not.
"""
def verifySignature(publicKey, message, signature):
    
    matchesSignature = True

    # Load Client's Public Key Object
    publicKey = serialization.load_pem_public_key(publicKey)
    
    try:
        publicKey.verify(
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
def verifyMAC(key, sentMessage, sentMAC):
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
def getMasterKey():
    return os.urandom(256)


"""
    Apply a message authentication code to a message using a key. To create the tag
    we are using the SHA256 Hash function.
    Args:
        key: A byte string
        message: A common string
    
    Returns:
        Message with a MAC in the end
"""
def applyMAC(key, message):
    h = hmac.HMAC(key, hashes.SHA256())
    
    messageAsBytes = str.encode(message)
    h.update(messageAsBytes)
    
    return b"".join([messageAsBytes, h.finalize()])  # to get the message with the MAC appended
    # return h.finalize()           #to get only the MAC  



"""
    Sign message with Client's Private Key

    Args:
        message: message to be signed

    Returns:
        Message Signature
"""
def signMessage(privateKey, message):
    
    return privateKey.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )