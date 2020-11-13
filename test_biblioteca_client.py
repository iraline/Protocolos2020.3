from biblioteca import Biblioteca
from VotingSession import VotingSession


privK = open('./keys/julio.pem', 'rb').read()
pubK = open('./keys/julio.pub', 'rb').read()
svPubK = open('./tests/keys/server_test_keys.pub', 'rb').read()

Client = Biblioteca("localhost", 1234, svPubK, clientPublicKey= pubK, clientPrivateKey= privK)



print("1o teste- Criar uma sessão. O id da sessao criada deve ser printado se a operação ocorreu com sucesso")
idzinho = Client.createVotingSession("melhor numero inteiro de 1 a 3", ["1", "2", "3"], "maxVotes", 1)
print(idzinho)

sessao = Client.checkSessionResult("melhor numero inteiro de 1 a 3")
print(sessao)

print("2o teste - Criar a conta de um cliente. True deve ser printado caso tudo ocorra como esperado")
status = Client.makeRegisterRequest("zezinho", "zezinho@gmail.com", "seila")
print(status)

print("3o teste - Efetuar o login de um cliente")
token = Client.makeLoginRequest("zezinho@gmail.com", "seila")
print(token)

print("4o teste - VOTAR EM UMA SESSAO")
boole = Client.sendVoteSession("000", "melhor numero inteiro de 1 a 3")
print(boole)

print("5o teste - Checar o resultado de uma sessao. Os candidatos devem ser printados se a operação ocorreu com sucesso")
sessao = Client.checkSessionResult("melhor numero inteiro de 1 a 3")
print(sessao.candidates)