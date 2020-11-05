from client import VotingClient
from server import VotingServer
import VotingSession

candidatos = ["julio", "divanilson", "erick jacquin", "caio", "xuxa"]

nonceSz = 48
tagSz = 32
headerSz = 2

privK = open('./tests/keys/client_test_keys.pem', 'rb').read()
pubK = open('./tests/keys/client_test_keys.pub', 'rb').read()
svPubK = open('./tests/keys/server_test_keys.pub', 'rb').read()
svPrivK = open('./tests/keys/server_test_keys.pem', 'rb').read()

testServer = VotingServer(svPrivK, svPubK)
testServer.sessions["concurso melhor pizza da minha rua"] = VotingSession.VotingSession("concurso melhor pizza da minha rua", candidatos, "maxVotes", maxVotes=19)
testClient = VotingClient(privK, pubK, svPubK)

# Teste quando a quantidade de votos desejada ainda não foi atingida
print("Primeiro teste")
fstPacket, nonce, HMACKey = testClient.verifySession("concurso melhor pizza da minha rua")
sndPacket = testServer.sendSessionResult(fstPacket)
print(testClient.receiveSessionResult(sndPacket, nonce, HMACKey))

# Teste quanda a quantidade de votos maxima foi atingida
print("")
print("Segundo teste")
testServer.sessions["concurso melhor pizza da minha rua"].candidates["julio"] = 10
testServer.sessions["concurso melhor pizza da minha rua"].candidates["erick jacquin"] = 9
fstPacket, nonce, HMACKey = testClient.verifySession("concurso melhor pizza da minha rua")
sndPacket = testServer.sendSessionResult(fstPacket)
requestedSession = testClient.receiveSessionResult(sndPacket, nonce, HMACKey)


print(requestedSession.candidates)