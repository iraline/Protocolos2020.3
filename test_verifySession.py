from client import VotingClient
from server import VotingServer

#Primeiro eh necessario verificar a tag

nonceSz = 48
tagSz = 32
headerSz = 2

privK = open('./tests/keys/client_test_keys.pem', 'rb').read()
pubK = open('./tests/keys/client_test_keys.pub', 'rb').read()
svPubK = open('./tests/keys/server_test_keys.pub', 'rb').read()
svPrivK = open('./tests/keys/server_test_keys.pem', 'rb').read()

testServer = VotingServer(svPrivK, svPubK)
testClient = VotingClient(privK, pubK, svPubK)

pckg = testClient.verifySession("concurso melhor pizza da minha rua")
b, nonce, sid, mckey = testServer.verifySessionTag(pckg)

if b:
    print("deu bom, eh o cliente")
    print(sid.decode())
else:
    print("fui hackeado, chama a tempest")
    print(sid.decode())