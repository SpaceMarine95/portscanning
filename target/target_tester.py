import socket

# Ask OS for the socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Perform DNS lookup and connect in one step
s.connect(('localhost', 12344)) # DNS lookup is done by the OS

# Send some data
s.sendall(b'Hello, world') # Data is sent in bytes

# Receive a response
data = s.recv(1024)
print('Received', repr(data))

# Close the socket
s.close()