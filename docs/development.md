## Mar 7 - Mar 10
### Done 
- simple packet header crafter
- simple target server code, docker image
- simple target tester developed

### Checked
- header crafter sends out packet as configured
    - ![header crafted](./images/packetcraft/SYN_Packet_flags.png)
    - ![header crafted](./images/packetcraft/SYN_Packets_crafted.png)
- server (target_server.py inside docker) responds to target_tester.py
    - ![response recvd](./images/target_test/test_tester.png)

### What to do next
- headercraft.py sent SYN packets doesn't get response, threeway handshake never answered back.     -> research and fix.