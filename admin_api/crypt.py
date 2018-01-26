#!/usr/bin/env python
"""An encryption module to help with authentication tokens."""

import os
import base64

# pylint: disable=E0401
from admin_api import ApiParser
# from pprint import pprint
# from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto import Random

# pylint: disable=E0001

def limitlines(inval):
    if not inval:
        return
    retval = ''
    lst = inval.split('\n')
    for index, value in enumerate(lst):
        if index < 2:
            retval += '%s\n' % value
    return retval

class Keypair(object):
    """Lets use public and private keys."""

    def __init__(self, cnfgfile=None, username=None, pubkeystring=None, checkexists=False, showlog=False):
        """Key Pair property initialize."""
        self.debuggenkey = False
        self.priv_key_sting = None
        self.priv_key_object = None
        self.exists = False
        self.username = username
        self.showlog = showlog
        if not username:
            self.keypairname = 'server_keys'
        elif username == 'mykeys':
            self.keypairname = 'mykeys'
        else:
            self.keypairname = 'user_%s' % (username)

        if cnfgfile:
            self.cnfgfile = cnfgfile
        else:
            oneup = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            self.cnfgfile = '%s/keys.cfg' % oneup
            self.log("config file is %s" % (self.cnfgfile))
        self.config = ApiParser()
        self.config.read(self.cnfgfile)

        if pubkeystring:
            self.log("Setting pubkeystring :\n%s" % (limitlines(pubkeystring)))
            self.public_key_string = pubkeystring
        else:
            # get the public key string from the config file
            self.log("get the public and private key from config file")
            self.public_key_string = self.config.safe_get(self.keypairname,
                                                          'public')
            self.priv_key_sting = self.config.safe_get(self.keypairname,
                                                       'private')
            self.log("public_key_string %s" % (bool(self.public_key_string)))
            self.log("priv_key_sting %s" % (bool(self.priv_key_sting)))
            if not self.priv_key_sting and not checkexists:
                self.log('Private key Not in config will generate')

        if not checkexists:
            if self.public_key_string:
                self.__importkeys()
            else:
                self.__genkeypair()

        self.log('Checking truthyness of public_key_string %s\n' % limitlines(self.public_key_string))
        if self.public_key_string:
            self.exists = True

    def __repr__(self):
        #re.compile("")
        retval = 'Keypair __repr__ :\n'
        retval += 'keypairname is "%s"\n' % (self.keypairname)
        retval += 'public_key_string is "%s"\n' % (limitlines(self.public_key_string))
        retval += 'priv_key_sting is "%s"\n' % (limitlines(self.priv_key_sting))
        return retval

    def __importkeys(self):
        """Import keys from config file."""
        if self.priv_key_sting:
            self.priv_key_object = RSA.importKey(self.priv_key_sting)
        self.log('__importkeys importing public key :\n%s' % (limitlines(self.public_key_string)))
        self.public_key_object = RSA.importKey(self.public_key_string)

    def __genkeypair(self):
        """No keys, so lets create them."""
        self.log("!!!!!!!!!!!!!!!!!!!!__genkeypair")
        # generate the key pair and write to config file
        random_generator = Random.new().read
        self.priv_key_object = RSA.generate(2048, random_generator)
        # self.log('key is %s' % (self.priv_key_object))
        self.public_key_object = self.priv_key_object.publickey()
        self.public_key_string = self.public_key_object.exportKey('PEM')
        self.log('public_key_string just generated %s' % (self.public_key_string))
        if self.keypairname not in self.config.sections():
            self.config.add_section(self.keypairname)
        self.log("Setting Public and private keys in __genkeypair")
        self.config.set(self.keypairname, 'public', self.public_key_string)
        self.priv_key_sting = self.priv_key_object.exportKey('PEM')
        self.config.set(self.keypairname, 'private', self.priv_key_sting)
        self.__writeconfig()

        if self.debuggenkey:
            self.log("can encrypt %s" % self.priv_key_object.can_encrypt())
            self.log("can sign %s" % self.priv_key_object.can_sign())
            self.log("has private %s" % self.priv_key_object.has_private())

            self.log('public key is %s' % self.public_key_string)

    def __writeconfig(self):
        """Write the configuration file."""
        configfile_fv = open(self.cnfgfile, 'w')
        self.config.write(configfile_fv)
        self.log("wrote config file %s" % (self.cnfgfile))

    def encrypt(self, string_in):
        """Encrypt a string."""
        enc_data = self.public_key_object.encrypt(string_in, 32)[0]
        enc_data = base64.b64encode(enc_data)

        if True:
            self.log("Encrypted data :")
            self.log(enc_data)
        return enc_data

    def decrypt(self, enc_data):
        """Decrypt a sting."""
        if self.priv_key_sting:
            self.showlog = True
            self.log("decrypt passed value, should be base64 encoded %s" % enc_data)
            enc_data = (base64.b64decode(enc_data))
            #self.log("decrypt b64 decoded string is %s, should look like blanked up blankedy?" % enc_data)
            net_decrypted = self.priv_key_object.decrypt(enc_data)
            self.log("decrypt string is %s" % net_decrypted)
            return net_decrypted
        else:
            self.log('No private key, most likely the wrong keypair being used')
        return None

    def get_pub_key(self):
        """Return The public key."""
        return self.public_key_string

    def saveserveronclient(self, token=None, pubkey=None):
        """Save the server public on client."""
        self.keypairname = 'server_keys'
        if self.keypairname not in self.config.sections():
            self.config.add_section(self.keypairname)
        if token:
            self.config.set(self.keypairname, 'token', token)

        if pubkey:
            #self.log('pubkey passed to saveserveronclient %s' % pubkey)
            self.config.set(self.keypairname, 'public', pubkey)

        if token or pubkey:
            # write the new token to config file
            self.__writeconfig()

    def saveclientonserver(self, token=None, username=None):
        """Save the client public key on server."""
        section = 'user_%s' % (username)
        if self.keypairname not in self.config.sections():
            self.config.add_section(self.keypairname)
        if token:
            self.config.set(self.keypairname, 'token', token)

        if self.public_key_string:
            self.config.set(self.keypairname, 'public', self.public_key_string)

        if token or self.public_key_string:
            # write the new token to config file
            self.__writeconfig()

    def checktoken(self):
        """Create a token for the client."""
        token = self.config.safe_get(self.keypairname, 'token')
        return token

    def gentoken(self):
        token = self.randstring(128)

        if self.keypairname not in self.config.sections():
            self.config.add_section(self.keypairname)

        # write the new token to config file
        self.config.set(self.keypairname, 'token', token)
        self.__writeconfig()
        return token

    @classmethod
    def randstring(cls, bytecount):
        """Classmethod to generate some random strings"""
        return base64.b64encode(Random.get_random_bytes(bytecount))

    def log(self, message):
        """Logg, control output here"""
        if self.showlog:
            show = "Keypair keyname %s -> %s" % (self.keypairname, message)
            print(show)


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
