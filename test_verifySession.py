from client import VotingClient

#Primeiro eh necessario verificar a tag

nonceSz = 48
tagSz = 32
headerSz = 2



privK = open('./tests/keys/client_test_keys.pem', 'rb').read()
pubK = open('./tests/keys/client_test_keys.pub', 'rb').read()
svPubK = open('./tests/keys/server_test_keys.pub', 'rb').read()
testClient = VotingClient(privK, pubK, svPubK)
msg = testClient.verifySession("concurso melhor pizza da minha rua")

strSz = int.from_bytes(msg[:headerSz], "little")

print("len: " + str(len(msg)))
print("header: " + str(strSz))
print("nonce: " + str(msg[headerSz:headerSz+nonceSz]))
print("sessionId: " + str(msg[headerSz+nonceSz:headerSz+nonceSz+strSz].decode()))
print("tag: " + str(msg[headerSz+nonceSz+strSz:headerSz+nonceSz+strSz+tagSz]))
print("encrypted mac key: " + str(msg[headerSz+nonceSz+strSz+tagSz:]))