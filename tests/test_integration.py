import unittest
from server import VotingServer
from client import VotingClient, verifySession, createVotingSession, receiveSessionResult
from VotingSession import VotingSession

class ClientServerIntegrationTest(unittest.TestCase):

    def setUp(self):

        with open('./tests/keys/server_test_keys.pem', 'rb') as serverPrivateKey: 
            self.serverPrivateKeyAsBytes = serverPrivateKey.read()

        with open('./tests/keys/server_test_keys.pub', 'rb') as serverPublicKey: 
            self.serverPublicKeyAsBytes = serverPublicKey.read()
            
        with open('./tests/keys/client_test_keys.pem', 'rb') as clientPrivateKey: 
            self.clientPrivateKeyAsBytes = clientPrivateKey.read()

        with open('./tests/keys/client_test_keys.pub', 'rb') as clientPublicKey: 
            self.clientPublicKeyAsBytes = clientPublicKey.read()

        self.server = self.loadVotingServer()
        self.client = self.loadVotingClient()


    # Read Server's Private and Public Keys to load VotingServer
    def loadVotingServer(self):

        usersPubKeys = 'usersPubKeys.json'
        userInfoFilePath = None

        return VotingServer(
            usersPubKeys, 
            userInfoFilePath,
            self.serverPrivateKeyAsBytes, 
            self.serverPublicKeyAsBytes
        )

    # Read Client's Private and Public Keys and Server's public key to load VotingClient
    def loadVotingClient(self):

        return VotingClient(
            self.clientPrivateKeyAsBytes,
            self.clientPublicKeyAsBytes,
            self.serverPublicKeyAsBytes,
        )


    def test_can_handle_a_verifySession_request(self):

        pckg, nonce, mcKey = verifySession("concurso melhor pizza da minha rua", self.serverPublicKeyAsBytes)
        b, nonce, sid, mckey = self.server.verifySessionTag(pckg)

        self.assertTrue(b)
    

    def test_client_can_create_a_session_request_and_server_create_it(self):

        sessionName = 'Pizza'
        candidates = ['Portuguesa', 'Calabresa', 'Carne de Sol']
        sessionMode = 'maxVotes'
        maxVotes = 10

        createSessionRequest = createVotingSession(
            self.serverPublicKeyAsBytes,
            sessionName,
            candidates,
            sessionMode,
            maxVotes=maxVotes
        )

        self.assertEqual(0, len(self.server.sessions))

        # Create Session
        self.server.createVotingSession(createSessionRequest)
        self.assertEqual(1, len(self.server.sessions))
        self.assertTrue(sessionName in self.server.sessions)


    def test_session_result(self):

        nonceSz = 48
        tagSz = 32
        headerSz = 2

        candidatos = [
            "julio", 
            "divanilson", 
            "erick jacquin", 
            "caio", 
            "xuxa"
        ]

        sessionName = "concurso melhor pizza da minha rua"
        self.server.sessions[sessionName] = VotingSession(
            sessionName, 
            candidatos, 
            "maxVotes", 
            maxVotes=19
        )

        # Teste quando a quantidade de votos desejada ainda não foi atingida

        fstPacket, nonce, HMACKey = verifySession(sessionName, self.serverPublicKeyAsBytes)
        sndPacket = self.server.sendSessionResult(fstPacket)
        
        self.assertIsNotNone(receiveSessionResult(sndPacket, nonce, HMACKey))
        print(receiveSessionResult(sndPacket, nonce, HMACKey))

        self.server.sessions[sessionName].candidates["julio"] = 10
        self.server.sessions[sessionName].candidates["erick jacquin"] = 9
        
        fstPacket, nonce, HMACKey = verifySession(sessionName, self.serverPublicKeyAsBytes)
        sndPacket = self.server.sendSessionResult(fstPacket)
        requestedSession = receiveSessionResult(sndPacket, nonce, HMACKey)
       
        # print(requestedSession.candidates)
