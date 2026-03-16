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
    host_ip = matches[4].group(0).replace("src ","")
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

def craft_TCP_header(src_ip, dst_ip, src_port=65432, dst_port=80):    
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
def send_SYN_probe(target_ip, dst_port):
    host_ip = get_host_ip() # roll back to function get_host_ip when dropping issue is fixed
    src_port = input("Select source port(1-65535): ")
    if src_port == "":
        src_port = 65432
    src_port = int(src_port)
    ip_header = craft_IP_header(host_ip, target_ip)
    tcp_header = craft_TCP_header(host_ip, target_ip, src_port, dst_port)
    packet = ip_header + tcp_header

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.sendto(packet, (target_ip, 0))
    print(f"SYN probe sent, {host_ip}:{src_port} -> {target_ip}:{dst_port}")

if __name__ == "__main__":
    targetIP = input("Target IP address: ").strip()
    dst_port = input("Destination port: ").strip() # types are refined within
    send_SYN_probe(targetIP, dst_port)
    
# Get the response