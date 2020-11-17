import auth
from create_session import createVotingSession
from verify_session import verifySessionResult  
from register import registerUser  
from login import loginUser  
import os
import sys

LOGIN = 'login'
REGISTER = 'register'
VERIFY_SESSION = 'verify_session'
CREATE_SESSION = 'create_sesion'
VOTE = 'vote' 

class App:

    def __init__(self):

        self.userToken = None
        self.clientPrivateKey = None

        # Text to be outputed in the main menu
        self.menuOptions = {
            LOGIN: "Logar",
            REGISTER: "Cadastrar",
            VERIFY_SESSION: "Verificar andamento da sessão",
            CREATE_SESSION: "Criar sessão",
            VOTE: "Votar em uma sessão",
        }

        self.host = 'localhost'
        self.port = 9595

        self.menuFunctions = {
            LOGIN: loginUser,
            REGISTER: registerUser,
            CREATE_SESSION: createVotingSession,
            VERIFY_SESSION: verifySessionResult,
        }

    
    def loadServerPublicKey(self):
        
        BASE_DIR = os.path.dirname(__file__)
        KEYS_DIR = os.path.join(BASE_DIR, 'keys')
        
        serverPubKeyPath = os.path.join(KEYS_DIR, 'server.pub')
        if not os.path.exists(serverPubKeyPath):
            print('Erro: Não foi possível encontrar a chave pública do servidor.')
            print('Erro: Crie um arquivo "server.pub" contendo a chave pública do servidor dentro da pasta keys')
            sys.exit(1)
            
        with open(serverPubKeyPath, 'rb') as serverPubKey:
            self.serverPublicKey = serverPubKey.read()


    def loadClientPrivateKey(self):
        pass

    
    def init_application(self):
        
        BASE_DIR = os.path.dirname(__file__)
        KEYS_DIR = os.path.join(BASE_DIR, 'keys')

        if not os.path.exists(KEYS_DIR):
            os.mkdir(KEYS_DIR)

        self.loadServerPublicKey()
        self.loadClientPrivateKey()


    def clearScreen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        

    def printMainMenu(self):

        self.clearScreen()
        header = f"{'=' * 10} Menu Principal {'=' * 10}"
        print (header)
        print()
        
        for n, option in enumerate(self.menuOptions.values()):
            print(f'{n + 1} - {option}')

        print()
        print (f"{'=' * len(header)}")


    def getUserChoiceFromMainMenu(self):

        chosenOptionStr = input("\n\nDigite a opção desejada:")
        while True:
            
            try:
                chosenOption = int(chosenOptionStr) - 1 
                if 0 <= chosenOption <= len(self.menuOptions) - 1:
                    break
            except Exception as  e:
                pass
                
            print("\nFalha ao escolher opção desejada.")
            chosenOptionStr = input(f"Por favor, digite um número entre 1 e {len(self.menuOptions)}:\n")

        menuOptionKeys = list(self.menuOptions.keys())
        return menuOptionKeys[chosenOption]

    
    def executeUserChoice(self, menuOptionKey):
        
        self.clearScreen()

        optionFunction = self.menuFunctions[menuOptionKey]
        optionFunction(self)


    def run_app(self):

        self.init_application()

        while True:
            self.printMainMenu()
            menuOptionKey = self.getUserChoiceFromMainMenu()
            self.executeUserChoice(menuOptionKey)

            input('\n\nDigite <Enter> para voltar ao menu principal.')
            

if __name__ == "__main__":
    App().run_app()