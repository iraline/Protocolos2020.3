import socket

"""
    Helper Base class for send and receiving data
"""
class BaseNetworkConnection:

    """
        Sent a piece of information

        This function first sends an 8-byte value containing the length of the packet.
        Then, it send the packet

        Args:
            packet: The packet to be sent
    """
    def send(self, packet):
        
        # Send packet length in the first 8 bytes
        # Then send the packet

        # Pad message with zeroes
        packetLength = '{:0>8d}'.format(len(packet))

        self.conn.send(packetLength.encode())
        self.conn.sendall(packet)


    """
        Receive a packet being written to socket 

        The sender is required to send the packet length in the first 8 bytes.
        Only then it can send the packet.

        Returns:
            Sent packet
    """
    def recv(self):
    
        buffer = b''

        # Get Size Length
        packetLength = int(self.conn.recv(8).decode())

        while len(buffer) < packetLength:

            data = self.conn.recv(1024)
            if not data:
                break

            buffer += data

        return buffer


    """
        Close connection
    """
    def close(self):
        self.conn.close()



"""
    Helper Class to communicate server to client
"""
class ServerNetworkConnetion(BaseNetworkConnection):

    def __init__(self, socket):

        self.conn = socket



"""
    Helper Class to communicate cliente to server
"""
class ClientNetworkConnection(BaseNetworkConnection):

    def __init__(self, host, port):

        self.host = host
        self.port = port

        self.conn = self.getConnection()

    """
        Make a connection to the specified server

        Returns:
            A socket connected to the host
    """
    def getConnection(self):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))
        
        return s