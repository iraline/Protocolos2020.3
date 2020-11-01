import secrets
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from exceptions import InvalidPacket
import cripto
import json
from VotingSession import VotingSession

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
        self.sessions = {}
 

    """
        Decrypt packets encrypted with the Server's Public Key

        Args:
            packet: Encrypted packet

        Returns:
            Decrypted packet
    """
    def decryptPacketWithServerPrivateKey(self, packet):
        return cripto.decryptPacketWithPrivateKey(self.privateKey, packet) 


    """
        Create Voting session from packet request

        Args:
            packet: Packet received without OP field (operation) 
        
        Returns:
            Session Name (ID) of created voting session

        Raises:
            InvalidPacket
    """
    def createVotingSession(self, packet):
        
        # Parse packet
        # encryptedHMACKey has length of 512 bytes and is located at the end of the packet
        # hmacTAG is 32 bytes (256 bits)
        # message is the remaining content which has variable size
    
        keyLength = 512
        tagLength = 32

        encryptedHMACKey = packet[-keyLength:]
        hmacTag = packet[-(keyLength + tagLength):-keyLength]
        message = packet[:-(keyLength + tagLength)]

        hmacKey = self.decryptPacketWithServerPrivateKey(encryptedHMACKey)        

        if not cripto.verifyTag(hmacKey, message, hmacTag):
            raise InvalidPacket
        
        # Get Session Options
        sessionInfo = json.loads(message.decode())

        # Check if session options sent make for a valid session
        if not self.validateVotingSessionOptions(sessionInfo):
            raise InvalidPacket

        session = VotingSession(
            sessionName=sessionInfo['sessionName'],
            candidates=sessionInfo['candidates'],
            sessionMode=sessionInfo['sessionMode'],
            maxVotes=sessionInfo.get('maxVotes', None),
            duration=sessionInfo.get('duration', None)
        )

        # Add Session
        self.sessions[session.id] = session

        return session.id


    """
        Validate if packet contains valid information to create a new Voting Session.
        Also validate if sessionName can be used or is already taken.

        Args:
            sessionInfo: Packet info containing options for a new voting session

        Returns:
            Wheter packet information is valid or not

    """
    def validateVotingSessionOptions(self, sessionInfo):
        
        # Session Name
        if 'sessionName' not in sessionInfo:
            return False
        
        if not isinstance(sessionInfo['sessionName'], str):
            return False

        if sessionInfo['sessionName'] in self.sessions:
            return False

        # Canditates
        if 'candidates' not in sessionInfo:
            return False

        if not isinstance(sessionInfo['candidates'], list):
            return False
    
        if len(sessionInfo['candidates']) < 2:
            return False

        for canditate in sessionInfo['candidates']:
            if not isinstance(canditate, str):
                return False

        # Session Finish Mode
        if not 'sessionMode' in sessionInfo:
            return False 
        
        if not isinstance(sessionInfo['sessionMode'], str):
            return False

        if sessionInfo['sessionMode'].lower() != 'maxvotes' and sessionInfo['sessionMode'].lower() != 'duration':
            return False

        if sessionInfo['sessionMode'] == 'maxVotes':
            if 'maxVotes' not in sessionInfo:
                return False
            if not isinstance(sessionInfo['maxVotes'], int):
                return False
            if not sessionInfo['maxVotes'] > 0:
                return False

        if sessionInfo['sessionMode'] == 'duration':
            if 'duration' not in sessionInfo:
                return False
            if not isinstance(sessionInfo['duration'], int):
                return False
            if not sessionInfo['duration'] > 0:
                return False

        return True

        
    """
        Verify if the tag sent from client from the verify session package is valid

        Args:
            The package sent from the client method "client.verifySession()"
        Returns:
            True if the tag is valid, else false
    """
    def verifySessionTag(self, package):
        nonceSz = 48
        tagSz = 32
        encryptedMacKeySz = 512

        if len(package) <= (nonceSz + tagSz + encryptedMacKeySz):
            return False
        
        message = package[:-(encryptedMacKeySz + tagSz)]
        sentTag = package[-(encryptedMacKeySz + tagSz):-encryptedMacKeySz]
        sentEncryptedMacKey = package[-encryptedMacKeySz:]

        nonce = message[:nonceSz]
        sessionId = message[nonceSz:]
        
        macKey = cripto.decryptPacketWithPrivateKey(self.privateKey, sentEncryptedMacKey)
        
        if cripto.verifyTag(macKey, message, sentTag):
            return True, nonce, sessionId, macKey
        else:
            return False, nonce, sessionId, macKey
