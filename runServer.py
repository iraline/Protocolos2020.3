
########## Server
from biblioteca import Biblioteca
import time

# Read Server's Private and Public Keys to load VotingServer
def loadVotingServer():
   
    usersPubKeys = 'usersPubKeys.json'
    userInfoFilePath = None
    with open('./keys/server.pem', 'rb') as privateKey: 
        with open('./keys/server.pub', 'rb') as publicKey: 
            return Biblioteca(
                'localhost',
                9595,
                publicKey.read(),
                userInfoFilePath,
                usersCredentials=usersPubKeys, 
                serverPrivateKey=privateKey.read(), 
                protocolMode='server'
            )

vs = loadVotingServer()

while True:
    print("Running Server")
    vs.listenClients()