import socket 
import _thread
import threading

def conexao(conn, cliente, tid):  # Funcao que será executada por nova thread

    cont = 0

    print("conectado por ")
    print(cliente)

    while True:

        msg = conn.recv(1024)
        if not msg:
            break

        print(msg)

        conn.send(msg)

    print("Cliente ")
    print(cliente)

    conn.close()  # Fecha a conexão
    _thread.exit()  # Termina thread


HOST = 'localhost'
PORT = 1234

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Criando o socket

try:
    s.bind((HOST, PORT))  # Vincula endereço com a porta

except socket.error as erro:  # Caso dê algum erro na vinculação, o programa é abortado
    print(erro)
    exit(0)

s.listen(999)  # Diz ao servidor quantas conexões serão

#Variáveis Globais#
tid = 0

while True:

    conn, addr = s.accept()  # Caso seja aceita ele retorna um objeto socket e um endereço
    _thread.start_new_thread(conexao, (conn, addr, tid))  # Criando nova thread
    tid += 1

conn.close
