#!/usr/bin/env python
"""An encryption module to help with authentication tokens."""

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

# pylint: disable=


class Keypair(RSA._RSAobj):
    """Lets use public and private keys."""

    def __init__(self, keyname='mykeys'):
        """Key Pair property initialize."""
        self.debuggenkey = False
        self.keypairname = 'mykeys'

        # get the public key string from the config file
        self.public_key_string = config.safe_get(self.keypairname, 'public')
        self.priv_key_sting = config.safe_get('mykeys', 'private')
        if not self.priv_key_sting:
            print('Private key Not in config will generate')

        if self.public_key_string:
            self.__importkeys()
        else:
            self.__genkeypair()

    def __importkeys(self):
        if self.priv_key_sting:
            self.private_key_object = RSA.importKey(self.priv_key_sting)
        self.public_key_object = RSA.importKey(self.public_key_string)

    def __genkeypair(self):
        # generate the key pair and write to config file
        random_generator = Random.new().read
        self.private_key_object = RSA.generate(4096, random_generator)
        print 'key is %s' % (self.private_key_object)
        self.public_key_object = self.private_key_object.publickey()
        self.public_key_string = self.public_key_object.exportKey('PEM')
        config.set('mykeys', 'public', self.public_key_string)
        self.priv_key_sting = self.private_key_object.exportKey('PEM')
        config.set('mykeys', 'private', self.priv_key_sting)

        configfile_fv = open(cnfgfile, 'w')
        config.write(configfile_fv)
        print "public and private key written"

        if self.debuggenkey:
            print "can encrypt %s" % self.private_key_object.can_encrypt()
            print "can sign %s" % self.private_key_object.can_sign()
            print "has private %s" % self.private_key_object.has_private()

            print 'public key is %s' % self.public_key_string

    def encrypt(self, string_in):
        """Encrypt a string."""
        enc_data = self.public_key_object.encrypt(string_in, 32)

        if self.debuggenkey:
            print "Encrypted data :"
            print enc_data
            print ""
        return enc_data

    def decrypt(self, enc_data):
        """Decrypt a sting."""
        if self.priv_key_sting:
            return self.private_key_object.decrypt(enc_data)
        return None


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
