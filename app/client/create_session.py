from biblioteca.biblioteca import Biblioteca

def getUserCreateSessionInput():

    print(f"{'=' * 10} Criando Sessão de Voto {'=' * 10}")

    sessionName = input("Digite o nome da sessão:")
    nCanditates = int(input("Digite o número de candidatos:"))

    candidates = []
    for i in range(0, nCanditates):

        while True:
            candidate = input(f"Digite o nome do {i +1}º candidato:")
            if len(candidate) < 1:
                print("O nome precisa ter pelo menos 1 caracter")
            else:
                candidates.append(candidate)
                break
        
    while True:
        
        print("\nDigite o modo de encerramento da sessão")
        print("1 - Total de votos")
        print("2 - Duração")
        print()

        sessionModeOption = int(input(""))
        if sessionModeOption == 1:
            sessionMode = 'maxVotes'
            break
        elif sessionModeOption == 2:
            sessionMode = 'duration'
            break
        else:
            print("Falha ao escolher modo de encerramento")

    if sessionMode.lower() == 'maxvotes':
        qnt = int(input("Digite a quantidade total de votos para encerrar a sessão"))
    else:
        qnt = int(input("Digite a duração total (em minutos) para encerrar a sessão"))

    
    sessionOptions = {
        'name': sessionName,
        'candidates': candidates,
        'sessionMode': sessionMode,
        'quantity': qnt,
    }

    return sessionOptions


def createVotingSession(app):
        
    sessionOptions = getUserCreateSessionInput()
    protocol = Biblioteca(
        app.host, 
        app.port, 
        app.serverPublicKey,
        protocolMode='client',
    )

    response = protocol.createVotingSession(
        sessionId=sessionOptions['name'],
        candidates=sessionOptions['candidates'],
        sessionMode=sessionOptions['sessionMode'],
        quantity=sessionOptions['quantity']
    )

    status, msg = response.split('-', 1)

    if status.lower() == 'ok':
        print(f"Sua sessão foi criada com sucesso.")
        print(f"ID da sessão: {msg}")
    else:
        if msg == 'This tag is invalid':
            msg = 'Falha de intergridade'
        elif msg == 'This session is invalid':
            msg = 'Sessão inválida'
        else:
            msg = 'Erro Desconhecido'

        print(f"Houve um erro ao criar sua sessão.\n{msg}")
        print(msg)
        print("Por favor, tente novamente.")




