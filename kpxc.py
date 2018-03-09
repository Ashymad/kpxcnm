import nacl.utils
import nacl.encoding
from nacl.public import PrivateKey, Box

import json
import base64 as b64
from subprocess import Popen, PIPE, STDOUT
import struct


class kpxc:
    CLIENT_ID_SIZE = 24
    NONCE_SIZE = 24
    def __init__(self):
        self.client_id = b64.b64encode(
            nacl.utils.random(self.CLIENT_ID_SIZE)).decode('UTF-8')
        self.privkey = PrivateKey.generate()
        self.kpxc_proxy = Popen('keepassxc-proxy', stdout=PIPE, stdin=PIPE,
                                stderr=STDOUT);
    def _send_message(self, message):
        message = json.dumps(message).encode('UTF-8')
        self.kpxc_proxy.stdin.write(struct.pack('I',len(message)))
        self.kpxc_proxy.stdin.write(message)
        self.kpxc_proxy.stdin.flush()
    def _read_message(self):
        txt_len_b = self.kpxc_proxy.stdout.read(4);
        if txt_len_b == 0: return
        txt_len = struct.unpack('i', txt_len_b)[0]
        return self.kpxc_proxy.stdout.read(txt_len).decode('UTF-8')
    def change_public_keys(self):
        self._send_message({
            'action' : 'change-public-keys',
            'publicKey' : self.privkey.public_key.encode(
                nacl.encoding.Base64Encoder).decode('UTF-8'),
            'nonce' : b64.b64encode(
                nacl.utils.random(self.NONCE_SIZE)).decode('UTF-8'),
            'clientID' : self.client_id
        })
        print(self._read_message())



