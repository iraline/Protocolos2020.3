import sys
sys.path.append("..") # Adds higher directory to python modules path.

from biblioteca import Biblioteca
from VotingSession import VotingSession

usersInfoStorage = "../usersInfoStorage.json"
usersCredentials = "../usersPubKeys.json"

svPubK = open('keys/server_test_keys.pub', 'rb').read()
svPrivK = open('keys/server_test_keys.pem', 'rb').read()

Server = Biblioteca("localhost", 1234, svPubK, usersInfoStorage, usersCredentials, svPrivK)


Server.listenClients()