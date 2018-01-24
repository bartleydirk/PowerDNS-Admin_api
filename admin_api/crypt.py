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

# pylint: disable=


class Keypair(object):
    """Lets use public and private keys."""

    def __init__(self, cnfgfile=None, keyname='mykeys', pubkeystring=None):
        """Key Pair property initialize."""
        self.debuggenkey = False
        self.priv_key_sting = None
        self.priv_key_object = None
        if keyname:
            self.keypairname = keyname
        else:
            self.keypairname = 'mykeys'

        if cnfgfile:
            self.cnfgfile = cnfgfile
        else:
            oneup = os.path.abspath(os.path.join(__file__, ".."))
            self.cnfgfile = '%s/keys.cfg' % oneup
            print "config file is %s" % (self.cnfgfile)
        self.config = ApiParser()
        self.config.read(self.cnfgfile)

        if not pubkeystring:
            # get the public key string from the config file
            self.public_key_string = self.config.safe_get(self.keypairname,
                                                          'public')
            self.priv_key_sting = self.config.safe_get(self.keypairname,
                                                       'private')
            if not self.priv_key_sting:
                print('Private key Not in config will generate')
        else:
            self.public_key_string = pubkeystring

        if self.public_key_string:
            self.__importkeys()
        else:
            self.__genkeypair()

    def __importkeys(self):
        if self.priv_key_sting:
            self.priv_key_object = RSA.importKey(self.priv_key_sting)
        self.public_key_object = RSA.importKey(self.public_key_string)

    def __genkeypair(self):
        # generate the key pair and write to config file
        random_generator = Random.new().read
        self.priv_key_object = RSA.generate(4096, random_generator)
        # print 'key is %s' % (self.priv_key_object)
        self.public_key_object = self.priv_key_object.publickey()
        self.public_key_string = self.public_key_object.exportKey('PEM')
        if self.keypairname not in self.config.sections():
            self.config.add_section(self.keypairname)
        self.config.set(self.keypairname, 'public', self.public_key_string)
        self.priv_key_sting = self.priv_key_object.exportKey('PEM')
        self.config.set(self.keypairname, 'private', self.priv_key_sting)

        configfile_fv = open(self.cnfgfile, 'w')
        self.config.write(configfile_fv)
        print "public and private key written"

        if self.debuggenkey:
            print "can encrypt %s" % self.priv_key_object.can_encrypt()
            print "can sign %s" % self.priv_key_object.can_sign()
            print "has private %s" % self.priv_key_object.has_private()

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
            return self.priv_key_object.decrypt(enc_data)
        return None

    def get_pub_key(self):
        """Return The public key."""
        return self.public_key_string


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
