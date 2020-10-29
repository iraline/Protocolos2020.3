import unittest
from server import VotingServer
from client import VotingClient


class ClientServerIntegrationTest(unittest.TestCase):

    def setUp(self):

        self.server = self.loadVotingServer()
        self.client = self.loadVotingClient()


    # Read Server's Private and Public Keys to load VotingServer
    def loadVotingServer(self):
        with open('./tests/keys/server_test_keys.pem', 'rb') as privateKey: 
            with open('./tests/keys/server_test_keys.pub', 'rb') as publicKey: 
                return VotingServer(privateKey.read(), publicKey.read())

    # Read Client's Private and Public Keys and Server's public key to load VotingClient
    def loadVotingClient(self):
        with open('./tests/keys/client_test_keys.pem', 'rb') as privateKey: 
            with open('./tests/keys/client_test_keys.pub', 'rb') as publicKey: 
                with open('./tests/keys/server_test_keys.pub', 'rb') as serverPublicKey: 
                    return VotingClient(privateKey.read(), publicKey.read(), serverPublicKey.read())

