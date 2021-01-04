# Cache-Poisoning-Attacks
Scapy Implementation of brute-force cache poisoning, Kaminsky attack, and SADDNS attack
This is a first commit, so there may be some bugs. I may eventually refactor this code into C, but I imagine that will be a significant undertaking. In any case, there are 3 .py files:

1. basic_poisoning.py--Brute-force cache-poisoning attack on a resolver with no source-port randomization. 
2. kamins.py--Kaminsky's cache-poisoning attack on a resolver with no source-port randomization. 
3. saddns.py--SADDNS cache-poisoning attack on a resolver with source-port randomization. 

This is a proof of concept more than anything, so don't expect that these attacks will work on an arbitrary recursive resolver without modification. For instance, the SADDNS implementation is tailored to the rate-limiting behavior of the resolver's OS/resolver implementation.
