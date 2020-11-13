from biblioteca import Biblioteca
from VotingSession import VotingSession


privK = open('./tests/keys/client_test_keys.pem', 'rb').read()
pubK = open('./tests/keys/client_test_keys.pub', 'rb').read()
svPubK = open('./tests/keys/server_test_keys.pub', 'rb').read()

Client = Biblioteca("localhost", 1234, svPubK, clientPublicKey= pubK, clientPrivateKey= privK)

# print("primeiro teste")
# sessao = Client.checkSessionResult("melhor pizza")
# print(sessao.candidates)

print("segundo teste")
idzinho = Client.createVotingSession("melhor numero inteiro de 1 a 3", ["1", "2", "3"], "maxVotes", 5)
print(idzinho)