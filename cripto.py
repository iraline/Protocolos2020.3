import secrets
import os
import cripto
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import exceptions


"""
    Generate nonce

    Returns
        48-byte-long-random bytearray to be used as nonce
"""


def generateNonce():
    return secrets.token_bytes(16)


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
    Encrypt message with the provided Public Key
    
    The padding part is extracted from an example in Cryptography's Docs
    OAEP padding is the recommended choice for new protocols/applications.
      
    Args:
        publicKey: Cryptography's Serialized Public Key object
        message: message to be encrypted 
    
    Returns:
        Encrypted message
"""


def encryptWithPublicKey(publicKey, message):

    return publicKey.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


"""
    Decrypt packets encrypted with the Public Key schemes

    The padding part is extracted from an example in Cryptography's Docs
    OAEP padding is the recommended choice for new protocols/applications.
   
    Args:
        packet: Encrypted packet to be decrypted 
    
    Returns:
        Decrypted message
"""


def decryptWithPrivateKey(privateKey, message):

    return privateKey.decrypt(
        message,
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
    except exceptions.InvalidSignature:
        matchesSignature = False

    return matchesSignature


"""
    Apply a message authentication code to a message using a key. To create the tag
    we are using the SHA256 Hash function.

    Args:
        key: A 32 byte string
        message: A common string
    
    Returns:
        The tag, A.K.A. MAC (Message Authentication Code)
"""


def createTag(key, message):
    h = hmac.HMAC(key, hashes.SHA256())

    if isinstance(message, str):
        message = str.encode(message)

    h.update(message)

    # return b"".join([message, h.finalize()])  # to get the message with the MAC appended
    return h.finalize()           # to get only the MAC


"""
    Verify if a message's MAC is valid, given a pre-shared key. To create the tag
    we are using the SHA256 Hash function.

    Args:
        key: A 32 byte string
        message: A byte string
        sentMAC: A byte string
    
    Returns:
        It returns True if the MAC is valid or False if it isn't
"""


def verifyTag(key, sentMessage, sentTag):
    h = hmac.HMAC(key, hashes.SHA256())

    messageAsBytes = sentMessage
    h.update(messageAsBytes)

    try:
        h.verify(sentTag)
        return True
    except exceptions.InvalidSignature:
        return False


"""
    Use the master key to create two others keys, that are going to be used to
    encryption and MAC

    Args:
        masterKey: A 32 byte key in byte format
        salt: A 16 byte salt in byte format
    Returns:
        Two 32 byte keys
"""


def generateKeysWithMS(masterKey, salt):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"",
    )
    bigKey = hkdf.derive(masterKey)
    return bigKey[:(len(bigKey)//2)], bigKey[(len(bigKey)//2):]


"""
    Generate a random master key of 256 bits (32 Bytes)

    Returns:
        It returns a master key in byte format
"""


def generateMasterKey():
    return os.urandom(32)


"""
    Generate a 32 byte key to be used in MAC

    Returns:
        It returns a key in byte format
"""


def generateMACKey():
    return os.urandom(32)


"""
    Generate a 16 byte salt
    
    Returns:
        Salt
"""


def generateSalt():
    return os.urandom(16)


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


"""
    Generate a Symmetric Key.
    
    Returns:
        A Symetric Key 
"""


def generateSymmetricKey():

    return os.urandom(32)


"""
    Encrypt a message with a Key.
    Args:
        key: A key that will be used for encryption
        nonce: Nonce used to encrypt the message in bytes
        message: Message to be encrypted in bytes
        
    Returns:
        Encrypted message
"""


def encryptMessageWithKeyAES(key, nonce, message):

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()

    return encryptor.update(message) + encryptor.finalize()


"""
    Decrypt a message with Symmetric Key.
    Args:
        key: A key that will be used for decryption
        nonce: Nonce used to encrypt the message in bytes
        message: Encrypted message in bytes
        
    Returns:
        Message dencrypted 
"""
def decryptMessageWithKeyAES(key, nonce, message):

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()

    return decryptor.update(message) + decryptor.finalize()
