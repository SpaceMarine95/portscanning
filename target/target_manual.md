# Example of "targets" which services can answer my SYN
1. Local lab VM running SSH; port 22/TCP
2. Web server, Simple Python server running on 80/TCP
3. A public server with an open port

Any which, it will respond with an SYN-ACK if open, or RST if closed.

# What I need for able to listen to and receive the response

1. A raw socket -> Listens for incoming TCP packets (Any inbound TCP traffic)
2. It must be able to parse the IP header and TCP header
3. Check the reply if it matches my probe

# Current task:
1. Build a simple Python-based TCP server, test locally.
2. Build another environment, separated from the scanner environment
3. Deploy ther server there and test