import unittest
from server import VotingServer
from client import VotingClient
from VotingSession import VotingSession

class ClientServerIntegrationTest(unittest.TestCase):

    def setUp(self):

        self.server = self.loadVotingServer()
        self.client = self.loadVotingClient()

    # Read Server's Private and Public Keys to load VotingServer
    def loadVotingServer(self):

        usersPubKeys = 'usersPubKeys.json'
        userInfoFilePath = None

        with open('./tests/keys/server_test_keys.pem', 'rb') as privateKey: 
            with open('./tests/keys/server_test_keys.pub', 'rb') as publicKey: 
                return VotingServer(
                    usersPubKeys, 
                    userInfoFilePath,
                    privateKey.read(), 
                    publicKey.read()
                )

    # Read Client's Private and Public Keys and Server's public key to load VotingClient
    def loadVotingClient(self):
        with open('./tests/keys/client_test_keys.pem', 'rb') as privateKey: 
            with open('./tests/keys/client_test_keys.pub', 'rb') as publicKey: 
                with open('./tests/keys/server_test_keys.pub', 'rb') as serverPublicKey: 
                    return VotingClient(privateKey.read(), publicKey.read(), serverPublicKey.read())


    def test_can_handle_a_verifySession_request(self):

        pckg, nonce, mcKey = self.client.verifySession("concurso melhor pizza da minha rua")
        b, nonce, sid, mckey = self.server.verifySessionTag(pckg)

        self.assertTrue(b)
    

    def test_client_can_create_a_session_request_and_server_create_it(self):

        sessionName = 'Pizza'
        candidates = ['Portuguesa', 'Calabresa', 'Carne de Sol']
        sessionMode = 'maxVotes'
        maxVotes = 10

        createSessionRequest = self.client.createVotingSession(
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

        fstPacket, nonce, HMACKey = self.client.verifySession(sessionName)
        sndPacket = self.server.sendSessionResult(fstPacket)
        
        self.assertIsNotNone(self.client.receiveSessionResult(sndPacket, nonce, HMACKey))
        print(self.client.receiveSessionResult(sndPacket, nonce, HMACKey))

        self.server.sessions[sessionName].candidates["julio"] = 10
        self.server.sessions[sessionName].candidates["erick jacquin"] = 9
        
        fstPacket, nonce, HMACKey = self.client.verifySession(sessionName)
        sndPacket = self.server.sendSessionResult(fstPacket)
        requestedSession = self.client.receiveSessionResult(sndPacket, nonce, HMACKey)
       
        print(requestedSession.candidates)


    def test_make_a_vote(self):
        # TODO: CREATE TEST