#!/usr/bin/env python3

from os import path, makedirs
import configparser
import pathlib
import sys
import argparse

from nacl.public import PrivateKey
from kpxcnm import Kpxcnm

cfg_path = path.expanduser("~/.config/kpxcnm/")

class Sub():
    @staticmethod
    def genkey(argv):
        return Kpxcnm._to_b64_str(bytes(PrivateKey.generate()))

    @staticmethod
    def init(argv):
        key = Sub.genkey(argv)
        k = Kpxcnm(PrivateKey(Kpxcnm._from_b64_str(key)))
        if k.change_public_keys() and k.associate():
            makedirs(cfg_path, exist_ok=True)
            with open(cfg_path + "keys.ini", "w") as f:
                f.write(f"[DEFAULT]\ndbid = {k.db_id}\nprivkey = {key}\n")
        return f"New config created at: {cfg_path}keys.ini"

    @staticmethod
    def get(argv):
        CONFIG = configparser.ConfigParser()
        CONFIG.read(cfg_path + "keys.ini")
        k = Kpxcnm(PrivateKey(Kpxcnm._from_b64_str(CONFIG['DEFAULT']['privkey'])),
                          CONFIG['DEFAULT']['dbid'])
        if k.change_public_keys() and k.test_associate(True):
            return k.get_logins(argv[2])[0]['password']

    @staticmethod
    def help(argv):
        return "KeePassXC Native Messaging Client CLI\n" \
        f"Usage: {argv[0]} {"|".join([func for func in dir(Sub) if callable(getattr(Sub, func)) and not func.startswith("__")])}"

def main(argv):
    if len(sys.argv) < 2:
        print(Sub.help(argv))
    elif hasattr(Sub, argv[1]):
        print(Sub.__dict__[argv[1]](argv))
    else:
        print(f"Unknown command: {argv[1]}")

if __name__ == "__main__":
    main(sys.argv)

