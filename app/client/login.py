import os
from biblioteca.biblioteca import Biblioteca

def getUserLoginInput():

    username = input("Digite o seu nome de usuário: ")
    password = input("Digite a sua senha: ")

    # while True:

    #     print("Digite o caminho absoluto para sua chave privada")
    #     userPrivateKeyPath = input("Ou o caminho relativo a partir da pasta keys: ")
        
    #     if not os.path.isabs(userPrivateKeyPath):
    #         userPrivateKeyPath = os.path.join('./keys', userPrivateKeyPath)

    #     if os.path.exists(userPrivateKeyPath):
    #         with open(userPrivateKeyPath, 'rb') as privateKey:
    #             userPrivateKey = privateKey.read()
    #             break
    #     else:
    #         print("Caminho invalido, tente novamente.")

    userInfo = {
        'username': username,
        'password': password,
        # 'privateKey': userPrivateKeyPath,
    }

    return userInfo


def loginUser(app):

    print(f"{'=' * 10} Registrar usuário {'=' * 10}")
    userInfo = getUserLoginInput()

    protocol = Biblioteca(
        app.host, 
        app.port, 
        app.serverPublicKey,
        # clientPrivateKey=userInfo['privateKey'],
        protocolMode='client',
    )

    status, token = protocol.makeLoginRequest(
        login=userInfo['username'],
        password=userInfo['password'],
    )

    if status:
        print("\nLogin realizado com sucesso.")
        app.userToken = token
    else:
        print("\nErro ao realizar login.")

    