import nacl.utils
from nacl import encoding
from nacl.public import PrivateKey, PublicKey, Box

import json
import base64 as b64
from subprocess import Popen, PIPE, STDOUT
import struct


class Kpxcnm:
    CLIENT_ID_SIZE = 24
    NONCE_SIZE = 24
    def __init__(self):
        self.client_id = self._to_b64_str(
            nacl.utils.random(self.CLIENT_ID_SIZE))
        self.privkey = PrivateKey.generate()
        self.pubkey = self.privkey.public_key.encode(
                            encoding.Base64Encoder).decode('UTF-8')
        self.kpxc_proxy = Popen('keepassxc-proxy', stdout=PIPE,
                                stdin=PIPE, stderr=STDOUT);
    @staticmethod
    def _to_b64_str(bytedata):
        return b64.b64encode(bytedata).decode('UTF-8')
    @staticmethod
    def _from_b64_str(bytedata):
        return b64.b64decode(bytedata.encode('UTF-8'))
    def _get_nonce(self):
        return self._to_b64_str(nacl.utils.random(self.NONCE_SIZE))
    def _send_message(self, message):
        message = json.dumps(message).encode('UTF-8')
        self.kpxc_proxy.stdin.write(struct.pack('I',len(message)))
        self.kpxc_proxy.stdin.write(message)
        self.kpxc_proxy.stdin.flush()
    def _read_message(self):
        txt_len_b = self.kpxc_proxy.stdout.read(4);
        if txt_len_b == 0: return
        txt_len = struct.unpack('i', txt_len_b)[0]
        return json.loads(
            self.kpxc_proxy.stdout.read(txt_len).decode('UTF-8'))
    def _send_encrypted_message(self, message):
        nonce = nacl.utils.random(self.NONCE_SIZE)
        self._send_message({
            'action'        : message['action'],
            'message'       : self._to_b64_str(self.kp_box.encrypt(
                json.dumps(message).encode('UTF-8'), nonce).ciphertext),
            'nonce'         : self._to_b64_str(nonce),
            'clientID'      : self.client_id,
            'triggerUnlock' : 'true'
        })
    def _read_encrypted_message(self):
        message = self._read_message()
        if 'message' in message:
            return json.loads(self.kp_box.decrypt(
                self._from_b64_str(message['message']),
                self._from_b64_str(message['nonce'])).decode('UTF-8'))
        return message
    def change_public_keys(self):
        self._send_message({
            'action'    : 'change-public-keys',
            'publicKey' : self.pubkey,
            'nonce'     : self._get_nonce(),
            'clientID'  : self.client_id
        })
        response = self._read_message()
        is_success = response['success'] == 'true'
        if is_success:
            self.kp_key = PublicKey(
                response['publicKey'].encode('UTF-8'),
                encoding.Base64Encoder)
            self.kp_box = Box(self.privkey, self.kp_key)
        return is_success
    def get_databasehash(self):
        self._send_encrypted_message({
            'action'    : 'get-databasehash'
        })
        response = self._read_encrypted_message()
        if response['success'] == 'true':
            return response['hash']
    def associate(self):
        self._send_encrypted_message({
            'action'    : 'associate',
            'key'       : self.pubkey
        })
    def generate_password(self):
        self._send_message({
            'action'    : 'generate-password',
            'nonce'     : self._get_nonce(),
            'clientID'  : self.client_id
        })
        response = self._read_encrypted_message()
        if response['success'] == 'true':
            return response['entries'][0]['password']
    def get_logins(self, url : str):
        self._send_encrypted_message({
            'action'    : 'get-logins',
            'url'       : url
        })
