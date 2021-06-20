#!/usr/bin/python3

import hashlib
from bitcoin import *

mystring = input('StringtoHash: ')
address = input('Address: ')
b1 = hashlib.sha256(mystring.encode()).hexdigest()
print(b1)

while b1 != 0:
    b1 = hashlib.sha256(b1.encode()).hexdigest()  # calculate next hash
    print(b1)
    myhex = b1
    myhex = myhex[:64]
    priv = myhex
    pub = privtopub(priv)
    pubkey1 = encode_pubkey(privtopub(priv), "bin_compressed")
    addr = pubtoaddr(pubkey1)
    print(addr)
    n = addr
    if n.strip() == address:
        print ("found!!!",addr,myhex)
        break
    aa = b1.encode('utf-8')
    aa = (hashlib.sha256(hashlib.sha256(aa).digest()).hexdigest())
    print(aa)
    myhex = aa
    myhex = myhex[:64]
    priv = myhex
    pub = privtopub(priv)
    pubkey1 = encode_pubkey(privtopub(priv), "bin_compressed")
    addr = pubtoaddr(pubkey1)
    print(addr)
    n = addr
    if n.strip() == address:
        print ("found!!!",addr,myhex)
        break


