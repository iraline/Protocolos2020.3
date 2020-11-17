from biblioteca.biblioteca import Biblioteca


def getUserVerifySessionInput():

    print(f"{'=' * 10} Verificar Sessão {'=' * 10}")
    
    sessionID = ''
    while len(sessionID) == 0:
        sessionID = input("Digite o id da sessão: ")

    return sessionID


def printSessionResult(sessionInfo):
    print(sessionInfo)

def verifySessionResult(app):

    STATUS_ERROR = -1
    STATUS_UNFINISHED_SESSION = 0
    STATUS_FINISHED_SESSION = 1
    STATUS_SESSION_DOES_NOT_EXIST = 2

    sessionId = getUserVerifySessionInput()
    protocol = Biblioteca(
        app.host, 
        app.port, 
        app.serverPublicKey,
        protocolMode='client'
    )

    status, msg = protocol.checkSessionResult(sessionId)

    if status == STATUS_ERROR:
        print("Erro ao realizar requisição")
    elif status == STATUS_UNFINISHED_SESSION:
        print("Sessão em andamento. Por favor, aguarde o termino.")
    elif STATUS_FINISHED_SESSION:
        printSessionResult(msg)
    elif STATUS_SESSION_DOES_NOT_EXIST:
        print("Sessão não existe.")
    else:
        print("Erro ao realizar requisição")


    print(msg)
    input('\n\nDigite <Enter> para voltar ao menu principal.')
