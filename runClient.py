from biblioteca import Biblioteca

# Read Client's Private and Public Keys and Server's public key to load VotingClient
def loadVotingClient():
    with open('./tests/keys/client_test_keys.pem', 'rb') as privateKey: 
        with open('./tests/keys/client_test_keys.pub', 'rb') as publicKey: 
            with open('./tests/keys/server_test_keys.pub', 'rb') as serverPublicKey: 
                return Biblioteca(
                    host='localhost',
                    port=9595,
                    clientPrivateKey=privateKey.read(), 
                    clientPublicKey=publicKey.read(), 
                    serverPublicKey=serverPublicKey.read()
                )


vc = loadVotingClient()

# Make Login Request
vc.makeLoginRequest('gabriel', '123123')

