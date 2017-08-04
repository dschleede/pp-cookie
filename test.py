#!/usr/bin/python
#
import base64
from Crypto.Cipher import ARC4
from Crypto import Random
from Crypto.Hash import SHA

key = b'sample'
nonce = Random.new().read(4)
#nonce = chr(0x05)+chr(0x00)+chr(0x00)+chr(0x00)
tempkey = SHA.new(key+nonce).digest()
cipher = ARC4.new(tempkey)
msg = cipher.encrypt(b'USERNAME'+chr(0x00)+b'192.168.0.1')
#print base64.b64encode(msg)
print msg
