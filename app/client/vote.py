from biblioteca.biblioteca import Biblioteca

def getUserVoteInput():

    sessionID = input("Digite o ID da sessão: ")
    candidate = int(input("Digite o numero do candidato: "))

    voteInfo = {
        'sessionID': sessionID,
        'candidate': f'{candidate:03}'
    }

    return voteInfo

def vote(app):

    print(f"{'=' * 10} Votar {'=' * 10}")
    
    if app.userToken is None:
        print("Nenhum Token está associado. Por favor, efeturar login")
        return

    voteInfo = getUserVoteInput()

    protocol = Biblioteca(
        app.host, 
        app.port, 
        app.serverPublicKey,
        protocolMode='client',
    )

    status = protocol.sendVoteSession(
        sessionId=voteInfo['sessionID'],
        vote=voteInfo['candidate'],
        token=app.userToken
    )

    if status:
        print("Voto computado com suceso.")
    else:
        print("Falha ao computar voto.")

