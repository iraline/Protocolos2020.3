import unittest
from client import VotingClient
from cryptography.hazmat.primitives import serialization


class VotingClientTest(unittest.TestCase):

    def setUp(self):

        self.client = self.loadVotingClient()
        
    # Read Client's Private and Public Keys and Server's public key to load VotingClient
    def loadVotingClient(self):

        with open('./tests/keys/client_test_keys.pem', 'rb') as privateKey: 
            with open('./tests/keys/client_test_keys.pub', 'rb') as publicKey: 
                with open('./tests/keys/server_test_keys.pub', 'rb') as serverPublicKey: 
                    return VotingClient(privateKey.read(), publicKey.read(), serverPublicKey.read())


    # Just checks wheter this test script is loading correctly
    def test_loads_test(self):
        self.assertNotEqual(2 + 2, 5)