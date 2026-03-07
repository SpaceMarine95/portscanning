"""
https://kanhayaky.medium.com/python-socket-programming-101-build-a-tcp-server-221ba72ee2f9

In Python, you create a socket by specifying two parameters:

Address Family: Defines the type of addresses the socket can communicate with.
- AF_INET: IPv4 addresses
- AF_INET6: IPv6 addresses
- AF_UNIX (or AF_LOCAL): Local inter-process communication on the same machine
Socket Type: Determines the communication protocol and characteristics.
- SOCK_STREAM: Uses TCP for reliable, connection-oriented communication
- SOCK_DGRAM: Uses UDP for fast, connectionless communication
- SOCK_RAW: Provides access to lower-level protocols for custom packet handling
"""

import socket

server_port = 12344

# Ask OS for the socket -> Bind it to a IP address, port -> Listen for incoming connections
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind( ('0.0.0.0',server_port) )
print(s)
s.listen(5) # parameter 5 -> maximum number of queued incoming connections.

while True:
    # Accept connection
    conn, addr = s.accept()
    print('Incoming transmission from: ', addr)

    # Receive data from the client
    data = conn.recv(1024) # 1024 -> Maximum amount of data (in bytes) to be received at once from the socket
    if not data:
        break
    
    print("Received: ", repr(data))

    # Send a response back to the client
    conn.sendall(b'hello, client')

    # Close the current client connection
    conn.close()

