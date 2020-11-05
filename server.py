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
from cerberus import Validator

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
        return cripto.decryptWithPrivateKey(self.privateKey, packet) 


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

        # Create Session Packet
        schema = {
            'sessionName': {
                'type': 'string', 
                'empty': False, 
                'maxlength': 200, 
                'required': True
            },
            'candidates': {
                'type': 'list', 
                'empty': False, 
                'schema': {'type': 'string'}, 
                'required': True
            },
            'sessionMode': {
                'type': 'string',
                'allowed': ['maxVotes', 'duration'],
                'required': True
            },
            'maxVotes': {
                'type': 'number',
                'dependencies': {'sessionMode': 'maxVotes'},
                'min': 1,
                'required': True,
                'excludes': 'duration'
            },
            'duration': {
                'type': 'number',
                'dependencies': {'sessionMode': 'duration'},
                'required': True,
                'excludes': 'maxVotes'
            }
        }

        # Validate if packet sent got all fields correctly 
        validator = Validator(schema)
        isPacketValid = validator.validate(sessionInfo)

        isSessionNameAvailalable = sessionInfo['sessionName'] not in self.sessions

        return isPacketValid and isSessionNameAvailalable
        

    """
        Verify if the tag sent from client from the verify session package is valid

        Args:
            The package sent from the client method "client.verifySession()"
        Returns:
            True if the tag is valid, else false, the nonce used, the sessionId and the mac key
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
        sessionId = message[nonceSz:].decode()
        
        macKey = cripto.decryptWithPrivateKey(self.privateKey, sentEncryptedMacKey)
        
        if cripto.verifyTag(macKey, message, sentTag):
            return True, nonce, sessionId, macKey
        else:
            return False, nonce, sessionId, macKey


    """
    Returns session result if the end condition is true

    Args:
        The packet sent from the client method "client.verifySession()"
    Retuns:
        The sorted list in a decrescent order of a tuple of candidates and number of votes
    """
    def sendSessionResult(self, packet):
        status, nonce, sessionId, macKey = self.verifySessionTag(packet)

        if status == False:
            # In this case we should return a packet signaling that the tag was invalid
            message = b"".join([b"ERROR", nonce])
            message = b"".join([message, b"Invalid tag"])
            InvalidTagPacket = "".join([message, cripto.createTag(macKey, message)])
            return InvalidTagPacket

        elif not sessionId in self.sessions:
            print("sei la")

        else:
            if self.sessions[sessionId].sessionMode.lower() == "maxvotes":
                # Hence, we must check if the maximum number of votes has been reached

                votes = self.sessions[sessionId].candidates.values()
                numVotes = sum(votes)

                if numVotes >= self.sessions[sessionId].maxVotes:
                    # Therefore, we must send the packet with the result

                    dumpedSession = json.dumps(self.sessions[sessionId].__dict__)
                    message = b"".join([nonce, dumpedSession.encode()])
                    tag = cripto.createTag(macKey, message)
                    sessionResultPacket = b"".join([message, tag])

                    return sessionResultPacket
            
                else:
                    # Therefore, we must send the packet signaling that the session isn't over yet
                    message = b"".join([b"ERROR", nonce])
                    message = b"".join([message, b"Unfinished session"])
                    UnfinishedSessionPacket = b"".join([message, cripto.createTag(macKey, message)])
                    return UnfinishedSessionPacket

        
            else:
                
                #-----------------------------------------#
                # THIS PART STILL NEEDS TO BE IMPLEMENTED #
                #-----------------------------------------#
                
                isSessionDurationOver = False 

                if isSessionDurationOver:
                    # Therefore, we must send the packet with the result

                    dumpedSession = json.dumps(self.sessions[sessionId].__dict__)
                    message = b"".join([nonce, dumpedSession.encode()])
                    tag = cripto.createTag(macKey, message)
                    sessionResultPacket = b"".join([message, tag])

                    return sessionResultPacket
                
                else:
                    # Therefore, we must send the packet signaling that the session isn't over yet
                    message = b"".join([b"ERROR", nonce])
                    message = b"".join([message, b"Unfinished session"])
                    UnfinishedSessionPacket = b"".join([message, cripto.createTag(macKey, message)])
                    return UnfinishedSessionPacket