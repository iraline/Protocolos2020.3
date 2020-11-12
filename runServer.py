
########## Server
from server import VotingServer
from client import VotingClient
from VotingSession import VotingSession
import time

# Read Server's Private and Public Keys to load VotingServer
def loadVotingServer():
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

vs = loadVotingServer()

while True:

    print ("Trying to initiate server")
    try:
        print("Running Server")
        vs.run()
    except:
        time.sleep(3)
        print("Trying again")