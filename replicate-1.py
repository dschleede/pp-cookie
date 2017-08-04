#!/usr/bin/python
#
import base64
from Crypto.Cipher import ARC4

key = b'sample'
cipher = ARC4.new(key)
msg = cipher.encrypt(chr(0x04)+chr(0x00)+chr(0x00)+chr(0x00)+b'USERNAME'+chr(0x00)+b'192.168.0.1')
print base64.b64encode(msg)
