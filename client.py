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
        nonceSz = 16
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

        if sessionMode.lower() == 'maxvotes':
            sessionInfo['maxVotes'] = maxVotes
        elif sessionMode.lower() == 'duration':
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
       
        message = {}
        message['login'] = bytes(login, encoding= 'utf-8')
        message['password'] = bytes(password, encoding= 'utf-8')
        message['nonce'] = bytes(nonce, encoding= 'utf-8')

        json_data = json.dumps(message)

        encryptedMessage = cripto.encryptMessageWithKeyAES(
            symetricKey, nonce, json_data)
        encryptedKey = cripto.encryptWithPublicKey(
            self.serverPublicKey, symetricKey)

        pack={}
        pack['encryptedMessage'] = bytes(encryptedMessage, encoding= 'utf-8')
        pack['encryptedKey'] = bytes(encryptedKey, encoding= 'utf-8')

        return json.dumps(pack)
    
    """              
        Encrypt the "id_client" with a symetric key, sign this message with your private key
        and send a generate MasterKey encrypted with the server's public key
    
        Args:
            self: Get the server's publicKey and client's privateKey
            id_client: User's uniqueidentification. 
        Returns:
            The packet that should be sent in bytearray format
    """

    def requestRegister(self, id_client):

        nonce = cripto.generateNonce()
        msKey = cripto.generateMasterKey()
     
        signId = cripto.signMessage(self.privateKey,id_client)

        symmetricHmac = cripto.generateKeysWithMS(msKey,nonce)
        
        symmetricKey = symmetricHmac[0]
      
        message = {}
        message['message'] = id_client #bytes(id_client, encoding= 'utf-8')
        message['hashMessage'] = signId #bytes(signId, encoding= 'utf-8')
        json_messageEncrypted = json.dumps(message)

        encryptedMessage = cripto.encryptMessageWithKeyAES( 
            symmetricKey, nonce, json_messageEncrypted)
        criptedMsKey = cripto.encryptWithPublicKey(self.serverPublicKey,msKey)

        pack={}
        pack['encryptedMessage'] = encryptedMessage
        pack['encryptedKey'] = criptedMsKey
        pack['nonce'] = nonce

        return json.dumps(pack)
