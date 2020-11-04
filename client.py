from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography import exceptions
import os
import cripto
import json


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

        self.privateKey = serialization.load_pem_private_key(
            clientPrivateKey, password=clientPassword)
        self.publicKey = serialization.load_pem_public_key(clientPublicKey)
        self.serverPublicKey = serialization.load_pem_public_key(
            serverPublicKey)

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

        Args:
            The session ID
        Returns:
            The packet that should be sent in bytearray format
    """

    def verifySession(self, sessionId):

        nonce = cripto.generateNonce()
        message = b"".join([nonce, sessionId.encode()])
        macKey = cripto.generateMACKey()
        tag = cripto.createTag(macKey, message)
        message = b"".join([message, tag])
        encryptedMacKey = cripto.encryptWithPublicKey(
            self.serverPublicKey, macKey)
        message = b"".join([message, encryptedMacKey])
        return message


    """
        Create a new voting session 

        Args:
            sessionName: Session Unique identifier
            candidates: List of strings containing candidates names.
            sessionMode: String that describes how this session will end. Either 'maxVotes' or 'duration'.
            maxVotes: Votes needed to end session. Used if sessionMode equals 'maxVotes'.
            duration: Time duration of the session in minutes. Used if sessionMode equals 'duration'.

        Returns:
            Packet containing a request for creating a new session.
    """

    def createVotingSession(self, sessionName, candidates, sessionMode, maxVotes=500, duration=60):

        sessionInfo = {
            'sessionName': sessionName,
            'candidates': candidates,
            'sessionMode': sessionMode
        }

        if sessionMode == 'maxVotes':
            sessionInfo['maxVotes'] = maxVotes
        elif sessionMode == 'duration':
            sessionInfo['duration'] = duration
        else:
            raise ValueError('Invalid value for \'sessionMode\'. Choose one of \'maxVotes\' or \'duration\'.')

        # Creating Packet 
        sessionInfoAsBytes = json.dumps(sessionInfo).encode()
        hmacKey = cripto.generateMACKey()
        tag = cripto.createTag(hmacKey, sessionInfoAsBytes)       
        encryptedHMACKey = cripto.encryptWithPublicKey(self.serverPublicKey, hmacKey)

        return b''.join([sessionInfoAsBytes, tag, encryptedHMACKey])
    
    
    """              
        Encrypt the login and password from the user with a symetric key. 
        The symetric key is encrypted with the server`s publickey

        Args:
            self: Get the server's publicKey
            login: User's login
            password User's password
            nonce: nonce received from server
        Returns:
            The packet that should be sent in bytearray format
    """

    def cryptCredentials(self, login, password, nonce):

        symetricKey = cripto.generateSymmetricKey()
        message = b"#".join([login, password, nonce])

        encryptedMessage = cripto.encryptMessageWithKeyAES(
            symetricKey, nonce, message)
        encryptedKey = cripto.encryptWithPublicKey(
            self.serverPublicKey, symetricKey)

        pack = b"-".join([encryptedMessage, encryptedKey])

        return pack
