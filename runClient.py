
from server import VotingServer
from client import VotingClient

# Read Client's Private and Public Keys and Server's public key to load VotingClient
def loadVotingClient():
    with open('./tests/keys/client_test_keys.pem', 'rb') as privateKey: 
        with open('./tests/keys/client_test_keys.pub', 'rb') as publicKey: 
            with open('./tests/keys/server_test_keys.pub', 'rb') as serverPublicKey: 
                return VotingClient(privateKey.read(), publicKey.read(), serverPublicKey.read())


vc = loadVotingClient()

# Make Login Request
vc.handleLoginRequest('gabriele', '123123')

