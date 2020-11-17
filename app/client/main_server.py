
########## Server
from biblioteca.biblioteca import Biblioteca
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


print("Initializing server application. Be sure that you got the usersPubKeys.json, server.pem, server.pub files setted up")

vs = loadVotingServer()

while True:
    print("Running Server")
    vs.listenClients()