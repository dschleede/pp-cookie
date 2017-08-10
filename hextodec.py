#!/usr/bin/python
import binascii
out = open('don2','wb')

dd = open('don1','r')
while True:
    a = dd.read(2)
    b = binascii.unhexlify(a)
    out.write(b)

