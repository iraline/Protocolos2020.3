from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography import exceptions
from exceptions import InvalidPacket
from VotingSession import VotingSession
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
        encryptedMacKey = cripto.encryptWithPublicKey(self.serverPublicKey, macKey)
        message = b"".join([message, encryptedMacKey])
        return message, nonce, macKey

    
    """
        Recieve session result packet

        Args:
            The packet sent from the server method "server.sendSessionResult()"
            The nonce used in "client.verifySession()"
            The HMACKey used in "client.verifySession()"
        Returns:
            Nothing, so it raises an exception (means that either the nonce, or the tag is invalid),
            Or a string signaling an error, 
            Or a session object
    """
    def receiveSessionResult(self, packet, lastNonce, HMACKey):
        
        errorSz = 5
        nonceSz = 48
        tagSz = 32
        invalidTagSz = len("Invalid tag")

        try:
            anErrorOccur = packet[:errorSz].decode() == "ERROR"
        except:
            anErrorOccur = False


        if anErrorOccur:

            nonce = packet[errorSz:(errorSz + nonceSz)]
            
            if nonce != lastNonce:
                raise InvalidPacket

            else:
                if cripto.verifyTag(HMACKey, packet[:-tagSz], packet[-tagSz:]):
                    if packet[(errorSz + nonceSz):(errorSz + nonceSz + invalidTagSz)] == "Invalid Tag":
                        return "The packet that you sent had an invalid tag"
                    else:
                        return "This session is still not finished"
                else:
                    raise InvalidPacket

        else:

            nonce = packet[:nonceSz]
            byteDumpedSession = packet[nonceSz:-tagSz]
            tag = packet[-tagSz:]

            if nonce != lastNonce:
                raise InvalidPacket
            
            else:
                if cripto.verifyTag(HMACKey, b"".join([nonce, byteDumpedSession]), tag):
                    
                    sessionDict = json.loads(byteDumpedSession.decode())

                    # Now, we have to convert the sessionDict to an object session

                    requestedSession = VotingSession(
                        sessionName= sessionDict["id"],
                        candidates= sessionDict["candidates"],
                        sessionMode= sessionDict["sessionMode"],
                        duration= sessionDict["duration"],
                        maxVotes= sessionDict["maxVotes"],
                        candidatesFormat= "Dictionary"
                    )

                    return requestedSession

                else:
                    raise InvalidPacket