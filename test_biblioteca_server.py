from biblioteca import Biblioteca
from VotingSession import VotingSession

usersInfoStorage = "./usersInfoStorage.json"
usersCredentials = "./usersPubKeys.json"

svPubK = open('./tests/keys/server_test_keys.pub', 'rb').read()
svPrivK = open('./tests/keys/server_test_keys.pem', 'rb').read()

Server = Biblioteca("localhost", 1234, svPubK, usersInfoStorage, usersCredentials, svPrivK)

# candidatosTeste = ["jacquin", "julio", "ana maria braga", "louro jose"]
# sessaoTeste = VotingSession("melhor pizza", candidatosTeste, "maxVotes", maxVotes= 10)
# Server.server.sessions["melhor pizza"] = sessaoTeste
# Server.server.sessions["melhor pizza"].candidates["julio"] = 10

Server.listenClients()