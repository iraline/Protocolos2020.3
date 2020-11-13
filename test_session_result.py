import client
import server
import VotingSession
import datetime
import time

candidatos = ["julio", "divanilson", "erick jacquin", "caio", "xuxa"]

nonceSz = 16
tagSz = 32
headerSz = 2

usersInfoStorage = "./usersInfoStorage.json"
usersCredentials = "./usersPubKeys.json"

svPubK = open('./tests/keys/server_test_keys.pub', 'rb').read()
svPrivK = open('./tests/keys/server_test_keys.pem', 'rb').read()

testServer = server.VotingServer(usersCredentials, usersInfoStorage, svPrivK, svPubK)
testServer.sessions["concurso melhor pizza da minha rua"] = VotingSession.VotingSession("concurso melhor pizza da minha rua", candidatos, "maxVotes", maxVotes=19)

# Teste quando a quantidade de votos desejada ainda não foi atingida
print("Teste maxVotes nao atingido")
fstPacket, nonce, HMACKey = client.verifySession("concurso melhor pizza da minha rua", svPubK)
sndPacket = testServer.sendSessionResult(fstPacket)
status, sndRet = client.receiveSessionResult(sndPacket, nonce, HMACKey)
if status <= 0:
    print(sndRet)
else:
    print(sndRet.candidates)

# # Teste quando a quantidade de votos maxima foi atingida
# print("")
# print("Teste maxVotes atingido")
# testServer.sessions["concurso melhor pizza da minha rua"].candidates["julio"] = 10
# testServer.sessions["concurso melhor pizza da minha rua"].candidates["erick jacquin"] = 9
# fstPacket, nonce, HMACKey = testClient.verifySession("concurso melhor pizza da minha rua", 
# sndPacket = testServer.sendSessionResult(fstPacket)
# status, sndRet = testClient.receiveSessionResult(sndPacket, nonce, HMACKey)
# if status <= 0:
#     print(sndRet)
# else:
#     print(sndRet.candidates)


# # # Teste quando a duracao ainda nao foi atingida
# # print("")
# # print("Teste duracao nao atingida")
# # testServer.sessions["melhor numero inteiro de 1 a 3"] = VotingSession.VotingSession("melhor numero inteiro de 1 a 3", ["1", "2", "3"], "duration", duration=0.1)
# # testServer.sessions["melhor numero inteiro de 1 a 3"].candidates["2"] = 1
# # fstPacket, nonce, HMACKey = testClient.verifySession("melhor numero inteiro de 1 a 3")
# # sndPacket = testServer.sendSessionResult(fstPacket)
# # status, sndRet = testClient.receiveSessionResult(sndPacket, nonce, HMACKey)
# # if status <= 0:
# #     print(sndRet)
# # else:
# #     print(sndRet.candidates)

# # time.sleep(10)
# # print("")
# # print("Teste duracao atingida")
# # fstPacket, nonce, HMACKey = testClient.verifySession("melhor numero inteiro de 1 a 3")
# # sndPacket = testServer.sendSessionResult(fstPacket)
# # status, sndRet = testClient.receiveSessionResult(sndPacket, nonce, HMACKey)
# # if status <= 0:
# #     print(sndRet)
# # else:
# #     print(sndRet.candidates)