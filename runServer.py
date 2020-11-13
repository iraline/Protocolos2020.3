
########## Server
from biblioteca import Biblioteca
import time

# Read Server's Private and Public Keys to load VotingServer
def loadVotingServer():
    usersPubKeys = 'usersPubKeys.json'
    userInfoFilePath = None
    with open('./tests/keys/server_test_keys.pem', 'rb') as privateKey: 
        with open('./tests/keys/server_test_keys.pub', 'rb') as publicKey: 
            return Biblioteca(
                'localhost',
                9595,
                publicKey.read(),
                userInfoFilePath,
                usersCredentials=usersPubKeys, 
                serverPrivateKey=privateKey.read(), 
            )

vs = loadVotingServer()

while True:
    print("Running Server")
    vs.listenClients()