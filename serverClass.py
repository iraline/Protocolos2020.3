'''import socket

#Create TCP/IP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = 'localhost'
port = 1234

try:
    # Bind the socket to the port
    variavel = (host, port)
    s.bind(variavel)
except socket.error as e:
    print(e)
    exit(0)

# Listen for incoming connections
s.listen(1)

# Wait for a connection
conn, addr = s.accept()
while True:
     # Receive the data with max b"1024
    data = conn.recv(1024)
    print("Received data: ", data.decode())
    conn.send(data)'''

#*****************************************************


'''
import thread
import threading
import socket

def conexao (conn, cliente, tid):  # Funcao que será executada por nova thread

    data = "Testethreads" + tid
    conn.send(data)

    conn.close() #Fecha a conexão
	thread.exit() #Termina thread


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  #Criando o socket

try:
	s.bind((HOST,PORT))  #Vincula endereço com a porta

except socket.error as erro: #Caso dê algum erro na vinculação, o programa é abortado
	print erro	
	exit(0)	

s.listen(USERS) #Diz ao servidor quantas conexões serão 

tid = 0

while True: 
	
	conn, addr = s.accept() #Caso seja aceita ele retorna um objeto socket e um endereço		
	thread.start_new_thread(conexao, (conn, addr, tid)) #Criando nova thread	
 	tid += 1

'''

import biblioteca

biblioteca.listenClients('localhost',1234)
