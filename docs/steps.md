# Phase 1 — Core SYN scanner

Build the smallest version that works.

It should:
1. accept target IP
2. accept a list or range of ports
3. craft TCP SYN packet
4. send packet
5. receive response
    classify:
        - SYN/ACK = open
        - RST = closed
        - no response / timeout = filtered or dropped

*** This phase is the heart of the project. ***

if ports get occupied during tests:
1. sudo lsof -iTCP -sTCP:LISTEN -n -P
2. kill -9 <PID>


# Phase 2 — Clean parsing and reporting
Once the scan works, make the output readable.

Example:
Target: 192.168.0.15
22/tcp   open
80/tcp   open
135/tcp  closed
445/tcp  open

Then slightly better:

Open ports:
22/tcp   SSH
80/tcp   HTTP
445/tcp  SMB

# Phase 3 — Basic service probing
After discovering open ports, do lightweight follow-up probing.

For example:
port 80/8080 → send simple HTTP request
port 21 → read FTP banner
port 25 → read SMTP banner
port 22 → read SSH banner

This is where the scanner starts becoming a recon tool, not just a packet demo.

# Phase 4 — Fingerprinting extras

Only after the basics are stable:

- TTL observations
- TCP window size notes
- timestamp analysis
- maybe simple OS hints

This should be treated as an advanced enrichment layer, not the core.

# Phase 5 — Speed improvements

Only then:

threading
async
better timeout handling
structured output like JSON
That order is clean and professional.