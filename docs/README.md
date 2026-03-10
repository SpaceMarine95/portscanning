# Pet project: Port scanner v2
## Overview
A port scanner, building and utlizing raw packets with Python native libraries.

For learning purposes of;
1. Packet crafting
    ![Packet Crafted](./images/packetcraft/SYN_Packet_header.png)
2. Network traffic
3. Defense Mechanics on network infrastructure
4. How to bypass the defense
5. And how to catch those bypassing traffics

## Features
1. SYN packet crafting
2. Dummy TCP server image build
3. WIP

## Project Architecture
- [Scanner core code files](core/)
- [Dummy target server code files](target/)
    - VM
    - Docker

## Project docs
- [Specific project plans](docs/steps.md)
- [Development Log](docs/development_log.md)
- [Snapshots, images](docs/images)

## How to use
1. build docker image from directory "repo/target/" (docker build -t simple-tcp-server)
2. run docker desktop if needed
3. start the image (docker run --rm -p 12345:12345 simple-tcp-server)
    ![docker_started](./images/target_test/test_docker.png)
4. test -> (sudo python3 target_tester.py)
    ![response recvd](./images/target_test/test_tester.png)    
    4. cd to core directory "repo/core/"
    5. sudo python3 header craft