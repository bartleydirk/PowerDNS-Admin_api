#!/usr/bin/env python

import sys
import os

from admin_api import fetch_remote, fetch_json, build_rrset, ApiParser
from pprint import pprint
from Crypto.Cipher import DES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto import Random

exepath = os.path.dirname(os.path.realpath(__file__))
cnfgfile = '%s/keys.cfg' % exepath
# print "config file is %s" % (cnfgfile)
config = ApiParser()
config.read(cnfgfile)

DBGGENKEY = False


def genkeypair():
    public_key_string = config.safe_get('mykeys', 'public')
    #print 'public_key_string %s' % public_key_string # [0, 50]
    if public_key_string:
        pubkey_read = True
    else:
        print "Public key Not in config, will generate"
        pubkey_read = False

    priv_key = None
    priv_key = config.safe_get('mykeys', 'private')
    #print 'priv_key %s' % priv_key #  [0, 50]
    if not priv_key:
        print "priv Not in config will generate"

    if pubkey_read:
        if priv_key:
            private_key_object = RSA.importKey(priv_key)
        public_key_object = RSA.importKey(public_key_string)
    else:
        # generate the key pair and write to config file
        random_generator = Random.new().read
        private_key_object = RSA.generate(4096, random_generator)
        print 'key is %s' % private_key_object
        public_key_object = private_key_object.publickey()
        public_key_string = public_key_object.exportKey('PEM')
        config.set('mykeys', 'public', public_key_string)
        priv_key = private_key_object.exportKey('PEM')
        config.set('mykeys', 'private', priv_key)

        configfile_fv = open(cnfgfile, 'w')
        config.write(configfile_fv)
        print "public and private key written"

    if DBGGENKEY:
        print "can encrypt %s" % private_key_object.can_encrypt()
        print "can sign %s" % private_key_object.can_sign()
        print "has private %s" % private_key_object.has_private()

        print 'public key is %s' % public_key_string

    enc_data = public_key_object.encrypt('A fun Sting to encrypt', 32)

    if DBGGENKEY:
        print "Encrypted data :"
        print enc_data
        print ""

    if priv_key:
        decrypted = private_key_object.decrypt(enc_data)
        print 'decrypted is %s' % decrypted


# print dir(RSA)
# iv = Random.get_random_bytes(8)
# des1 = DES.new('01234567', DES.MODE_CFB, iv)
# des2 = DES.new('01234567', DES.MODE_CFB, iv)
# text = 'abcdefghijklmnop'
# print 'text is "%s"' % text
# cipher_text = des1.encrypt(text)
# print cipher_text
# decrypted = des2.decrypt(cipher_text)
# print decrypted

