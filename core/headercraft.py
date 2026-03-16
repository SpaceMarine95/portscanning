import socket
import subprocess
import re
import struct

"""
1. accept target IP
2. accept a list or range of ports
3. craft TCP SYN packet
4. send packet
5. receive response
    classify:
        - SYN/ACK = open
        - RST = closed
        - no response / timeout = filtered or dropped
"""
def get_host_ip():
    command = "ip route show".split()
    runner = subprocess.run(command, stdout=subprocess.PIPE).stdout.decode() # gives the "ip route show" bash execution results
    pattern = r"(\d+\.\d+\.\d+\.\d+)"
    matches = list(re.finditer(pattern, runner))
    # print(f"IP pattern match: {matches}")
    host_ip = matches[2].group(0).replace("src ","")
    print(f"Host IP: {host_ip}")
    # returns the first IP address (Default) as a str type
    return host_ip


def craft_IP_header(host_ip, target_ip):
    # IP header fields
    ip_fields = {
        "version": 4,
        "ihl" : 5, # min: 5 - max: 20
        "tos" : 0, # DSCP + ESN
        "total_length": 0, # kernel calculates this
        "id" : 12345,
        "frag_off" : 0,
        "ttl" : 64,
        "protocol" : socket.IPPROTO_TCP,
        "checksum" : 0, # kernel does the checksum
        "src_ip" : socket.inet_aton(host_ip.strip()), # src IP -> 32-bit bin
        "dst_ip" : socket.inet_aton(target_ip.strip()) # dst IP -> 32-bit bin
    }
    
    ver_ihl = (ip_fields["version"] << 4) + ip_fields["ihl"] # ver, ihl share a byte.

    # Pack fields into a header
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        ip_fields["tos"],
        ip_fields["total_length"],
        ip_fields["id"],
        ip_fields["frag_off"],
        ip_fields["ttl"],
        ip_fields["protocol"],
        ip_fields["checksum"],
        ip_fields["src_ip"],
        ip_fields["dst_ip"]
    )
    return ip_header

# Craft SYN packets
def checksum(data: bytes) -> int:
    # pad to even length
    if len(data) % 2 == 1:
        data += b'\x00'

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
        total = (total & 0xffff) + (total >> 16)

    return (~total) & 0xffff

def craft_TCP_header(src_ip, dst_ip, src_port=12345, dst_port=80):    
    # TCP header fields
    tcp_fields = {
        "src_port" : int(src_port),
        "dst_port" : int(dst_port),
        "syn_seq" : 454,
        "ack_seq" : 0,
        "doff" : 5, # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
        # tcp flags
        "flag_fin" : 0,
        "flag_syn" : 1,
        "flag_rst" : 0,
        "flag_psh" : 0,
        "flag_ack" : 0,
        "flag_urg" : 0,
        # end of flags
        "max_window" : socket.htons(5840), # maximum allowed window size
        "checksum" : 0,
        "urg_ptr" : 0,
    }
    
    payload = b""

    tcp_offset_res = (tcp_fields["doff"] << 4 ) + 0
    tcp_flags = (tcp_fields["flag_fin"] + 
                 (tcp_fields["flag_syn"] << 1) + 
                 (tcp_fields["flag_rst"] << 2) + 
                 (tcp_fields["flag_psh"] << 3) + 
                 (tcp_fields["flag_ack"] << 4) + 
                 (tcp_fields["flag_urg"] << 5))
    
    tcp_header = struct.pack("!HHLLBBHHH",
                             tcp_fields["src_port"],
                             tcp_fields["dst_port"],
                             tcp_fields["syn_seq"],
                             tcp_fields["ack_seq"],
                             tcp_offset_res,
                             tcp_flags,
                             tcp_fields["max_window"],
                             tcp_fields["checksum"],
                             tcp_fields["urg_ptr"])
    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        len(tcp_header) + len(payload)
    )

    tcp_fields["checksum"] = checksum(pseudo_header + tcp_header + payload)
    print(f"TCP Checksum calculated: {tcp_fields["checksum"]}")
    tcp_header = struct.pack("!HHLLBBHHH",
                             tcp_fields["src_port"],
                             tcp_fields["dst_port"],
                             tcp_fields["syn_seq"],
                             tcp_fields["ack_seq"],
                             tcp_offset_res,
                             tcp_flags,
                             tcp_fields["max_window"],
                             tcp_fields["checksum"],
                             tcp_fields["urg_ptr"])
    print("TCP header is now repacked with the real checksum!")
    return tcp_header

# Send the crafted packet
def send_SYN_probe(host_port, target_ip, target_port):
    host_ip = get_host_ip() # roll back to function get_host_ip when dropping issue is fixed
    
    if host_port == "" or None:
        host_port = input("Select source port(1-65535): ")
        if host_port == "" or None:
            host_port = 65432
    host_port = int(host_port)
    ip_header = craft_IP_header(host_ip, target_ip)
    tcp_header = craft_TCP_header(host_ip, target_ip, host_port, target_port)
    packet = ip_header + tcp_header

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.sendto(packet, (target_ip, 0))
    print(f"SYN probe sent, {host_ip}:{host_port} -> {target_ip}:{target_port}")


# Feature add: Receive response and read the flags
def receive_response(host_port, timeout=2):
    r = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    r.settimeout(timeout)
    try:
        while True:
            raw_data, addr = r.recvfrom(65535)
            # raw_data = IP header + TCP header
            ihl = (raw_data[0] & 0x0F) * 4 # IHL field
            tcp_data = raw_data[ihl:]

            # Unpack TCP header
            tcp_header = struct.unpack("!HHLLBBHHHH", tcp_data[:22])
            recv_dst_port = tcp_header[0]
            recv_src_port = tcp_header[1]
            flags = tcp_header[5]

            if recv_dst_port == host_port: #Right address for us -> checkout the flags
                return flags
    except socket.timeout:
        return None # Filtered or no response

def classify_response(flags):
    if flags is None:
        return "filtered"
    
    SYN = (flags >> 1) & 1
    ACK = (flags >> 4) & 1
    RST = (flags >> 2) & 1

    if SYN & ACK:
        return "open"
    elif RST:
        return "closed"
    else:
        return "filtered"
# should we complete the handshake?
def scan_port(host_port, target_ip, target_port=12345, stealth=True):
    
    if stealth:
        # Block kernel RST send
        try:
            subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "--sport", str(host_port), "--tcp-flags", "RST", "RST", "-j", "DROP"])
        except FileNotFoundError:
            print("iptables command not found. Please install iptable (sudo apt install iptables).")

    try:
        send_SYN_probe(host_port, target_ip, target_port)
        flags = receive_response(host_port, timeout=2)
        result = classify_response(flags)
        print(f"Target port {host_port}: {result}")
        return result
    finally:
        if stealth:
            subprocess.run(["iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", str(host_port), "--tcp-flags", "RST", "RST", "-j", "DROP"])

def stealth_checker(response):
    if response in ["Y","y","YES","yes","ok", "o"]:
        stealth_check = True
    elif response in ["N", "n", "NO", "no", "nope", "x"]:
        stealth_check = False
    else:
        print("Check your input again please.")
    return stealth_check

if __name__ == "__main__":
    target_ip = input("Target IP address: ").strip()
    target_port = input("Target port: ").strip() # types are refined within
    stealth_check = stealth_checker(input("Stealth Scan? Y/n: ").strip())
    host_port = input("Host port (Must be unoccupied): ")
    scan_port(host_port, target_ip, target_port=target_port, stealth=stealth_check)