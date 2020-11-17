import os
from biblioteca.biblioteca import Biblioteca


def getUserRegisterInput():

    userID = input("Digite o seu identificador: ") 
    
    username = input("Digite o seu nome de usuário: ")
    password = input("Digite a sua senha: ")

    # Check if file exists
    while True:
        print("Digite o caminho absoluto para sua chave privada")
        userPrivateKeyPath = input("Ou o caminho relativo a partir da pasta keys: ")
        
        if not os.path.isabs(userPrivateKeyPath):
            userPrivateKeyPath = os.path.join('./keys', userPrivateKeyPath)

        if os.path.exists(userPrivateKeyPath):
            with open(userPrivateKeyPath, 'rb') as privateKey:
                userPrivateKey = privateKey.read()
                break
        else:
            print("Caminho invalido, tente novamente.")

    userInfo = {
        'id': userID,
        'privateKey': userPrivateKey,
        'username': username,
        'password': password
    }

    return userInfo


def registerUser(app):

    print(f"{'=' * 10} Registrar usuário {'=' * 10}")
    userInfo = getUserRegisterInput()

    protocol = Biblioteca(
        app.host, 
        app.port, 
        app.serverPublicKey,
        clientPrivateKey=userInfo['privateKey'],
        protocolMode='client',
    )

    response, description = protocol.makeRegisterRequest(
        userID=userInfo['id'],
        login=userInfo['username'],
        password=userInfo['password'],
    )

    if response:
        print("\nCadastro realizado com sucesso.")
    else:
        print("\nErro ao realizar cadastro.")
        print(description)

    