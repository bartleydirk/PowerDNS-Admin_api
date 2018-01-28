#!/usr/bin/env python
"""An encryption module to help with authentication tokens."""

import os
import base64
import uuid
import json
from datetime import datetime, timedelta
from pprint import pformat

# pylint: disable=E0401

from Crypto import Random
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA

from admin_api import ApiParser

# pylint: disable=E0001

TMEFMT = "%Y %m %d %H:%M:%S"


def limitlines(inval):
    """Limit the number of lines displayed for some of the log."""
    if inval:
        retval = ''
        lst = inval.split('\n')
        for index, value in enumerate(lst):
            if index < 2:
                retval += '%s\n' % value
    else:
        retval = None
    return retval


class Keypair(object):
    """Lets use public and private keys."""

    # pylint: disable=R0913,R0902
    def __init__(self, cnfgfile=None, username=None, pubkeystring=None, uuid_=None, checkexists=False, showlog=False,
                 isclient=False):
        """Key Pair property initialize."""
        self.md5 = MD5.new()
        self.debuggenkey = False
        self.priv_key_string = None
        self.priv_key_object = None
        self.username = username
        self.showlog = showlog
        self.public_key_object = None
        self.priv_key_object = None
        self.public_key_string = pubkeystring
        self.uuid = uuid_
        self.isclient = isclient
        self.userpair = False
        if self.isclient:
            self.logfile = '/home/dbartley/projects/PowerDNS-Admin_api/afile.log'
        else:
            self.logfile = '/home/dbartley/projects/PowerDNS-Admin/afile.log'

        if not username:
            self.keypairname = 'server_keys'
        elif username == 'mykeys':
            self.keypairname = 'mykeys'
            self.userpair = True
        else:
            self.keypairname = 'user_%s' % (username)
            self.userpair = True
        self.sever_pair_onclient = not self.userpair and self.isclient
        self.client_pair_onserver = self.userpair and not self.isclient

        if cnfgfile:
            self.cnfgfile = cnfgfile
        else:
            oneup = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            self.cnfgfile = '%s/keys.cfg' % oneup
            self.log("config file is %s" % (self.cnfgfile))
        self.config = ApiParser()
        self.config.read(self.cnfgfile)
        # do not want the keys from config if on client getting public key from server
        if not pubkeystring:
            self.__getkeysfromconfig()

        if not checkexists:
            self.initbefore()

        self.log('Checking truthyness of public_key_string\n%s' % limitlines(self.public_key_string))

    def initbefore(self):
        """Init Steps when init can be done from init."""
        if self.public_key_string:
            # we wont pass a public key string if it is in the config
            self.log("Setting pubkeystring :\n%s" % (limitlines(self.public_key_string)))
            self.__rsaobjects_fromkeystrings()

        # if we neither have a public key string or an object, we need to generate.
        if not self.exists and not self.sever_pair_onclient:
            self.__genkeypair()

    def initafter(self, pubkey, uuid_):
        """Initialize After for client when first step is to check existence."""
        self.log("initafter initializing after init, must be in client %s" % (bool(self.public_key_string)))
        if pubkey:
            self.public_key_string = pubkey
            self.uuid = uuid_
            self.saveserveronclient(pubkey=pubkey, uuid_=uuid_)
        self.__rsaobjects_fromkeystrings()

    def __repr__(self):
        """Representation of the class."""
        retval = 'Keypair __repr__ :\n'
        retval += '    keypairname is "%s"\n' % (self.keypairname)
        retval += '    public_key_string is "%s"\n' % (limitlines(self.public_key_string))
        retval += '    priv_key_string is "%s"\n' % (limitlines(self.priv_key_string))
        return retval

    def __rsaobjects_fromkeystrings(self):
        """Import keys from config file."""
        # self.showlog = True
        self.log('__rsaobjects_fromkeystrings importing public key :\n%s' % (limitlines(self.public_key_string)))
        self.public_key_object = RSA.importKey(self.public_key_string)
        if self.priv_key_string:
            self.__privateonwronghost()
            self.priv_key_object = RSA.importKey(self.priv_key_string)

    def __getkeysfromconfig(self):
        """Import the keys from the config file."""
        # get the public key string from the config file
        self.log("__getkeysfromconfig get the public and private key from config file")
        self.public_key_string = self.config.safe_get(self.keypairname, 'public')
        self.priv_key_string = self.config.safe_get(self.keypairname, 'private')
        self.uuid = self.config.safe_get(self.keypairname, 'uuid')
        self.log("__getkeysfromconfig public_key_string %s" % (bool(self.public_key_string)))
        self.log("__getkeysfromconfig priv_key_string %s" % (bool(self.priv_key_string)))
        # datetime.strptime(, TMEFMT)
        if self.public_key_string:
            # create the python object from the string
            self.__rsaobjects_fromkeystrings()
        if self.client_pair_onserver and self.tokentime:
            expiretime = datetime.strptime(self.tokentime, TMEFMT)
            self.log('__getkeysfromconfig -> expire check %s' % (expiretime))
            self.log('__getkeysfromconfig -> expire check %s' % (expiretime.strftime(TMEFMT)))
            elapse = datetime.now() - expiretime
            self.log('__getkeysfromconfig -> expire elapse %s' % (elapse))
            if elapse > timedelta(0, 600):
                self.log('__getkeysfromconfig -> token expired')
                self.config.remove_option(self.keypairname, 'token')
                self.config.remove_option(self.keypairname, 'tokentime')
                self.__writeconfig()
            else:
                self.log('__getkeysfromconfig -> token good')

    @property
    def exists(self):
        """Property for if the public key string or object exists."""
        retval = False
        if self.public_key_string or self.public_key_object:
            retval = True
        return retval

    def __privateonwronghost(self):
        """Private keys should not be on the wrong host."""
        if self.sever_pair_onclient or self.client_pair_onserver:
            self.log("!!!!!!!!!!!!!!!!!!!!__genkeypair should never get here")
            raise Exception('should never get here sever_pair_onclient or client_pair_onserver')

    def __genkeypair(self):
        """No keys, so lets create them."""
        # generate the key pair and write to config file
        self.__privateonwronghost()
        random_generator = Random.new().read
        self.uuid = str(uuid.uuid4())
        self.priv_key_object = RSA.generate(2048, random_generator)
        # create public key object from method in private key object
        self.public_key_object = self.priv_key_object.publickey()

        # We want the public key string for distribution, but not the private
        self.public_key_string = self.public_key_object.exportKey('PEM')
        self.log('public_key_string just generated %s\n' % (limitlines(self.public_key_string)))

        # write to the config file
        if self.keypairname not in self.config.sections():
            self.config.add_section(self.keypairname)
        self.log("__genkeypair Setting Public and private keys in")
        self.config.set(self.keypairname, 'public', self.public_key_string)
        self.priv_key_string = self.priv_key_object.exportKey('PEM')
        self.config.set(self.keypairname, 'private', self.priv_key_string)
        self.config.set(self.keypairname, 'uuid', self.uuid)
        self.__writeconfig()

        if self.debuggenkey:
            self.log("__genkeypair can encrypt %s" % self.priv_key_object.can_encrypt())
            self.log("__genkeypair can sign %s" % self.priv_key_object.can_sign())
            self.log("__genkeypair has private %s" % self.priv_key_object.has_private())
            self.log('__genkeypair public key is %s' % self.public_key_string)

    def __writeconfig(self):
        """Write the configuration file."""
        configfile_fv = open(self.cnfgfile, 'w')
        self.config.write(configfile_fv)
        self.log("wrote config file %s" % (self.cnfgfile))

    def encrypt(self, string_in):
        """Encrypt a string, and encode it in base64."""
        enc_data = self.public_key_object.encrypt(string_in, 32)[0]
        enc_data = base64.b64encode(enc_data)
        return enc_data

    def decrypt(self, enc_data):
        """Decrypt a sting."""
        if self.priv_key_string:
            # self.showlog = True
            self.log("decrypt passed value, should be base64 encoded %s" % enc_data)
            # the data is a tuple of length one
            enc_data = (base64.b64decode(enc_data))
            net_decrypted = self.priv_key_object.decrypt(enc_data)
            return net_decrypted
        else:
            self.log('No private key, most likely the wrong keypair being used')
        return None

    def sign(self, tosign_in):
        """Sign a string."""
        # tosign_in = 'tosign_inasdfasdfasdfasdfasdf'
        self.md5.update(tosign_in)
        tosign_md5 = self.md5.digest()
        maxsize = self.priv_key_object.size()
        self.log('sign -> maxsize %s' % maxsize, level=6)
        self.log('sign -> tosign_md5 %s' % tosign_md5, level=6)
        random_generator = Random.new().read
        binary_signature = json.dumps(self.priv_key_object.sign(tosign_md5, random_generator))
        self.log('sign -> binary_signature pformat \n%s' % pformat(binary_signature), level=6)
        # self.log('sign -> binary_signature type \n%s' % type(binary_signature), level=6)
        encoded_signature = base64.b64encode(binary_signature)
        self.log('sign -> returning signature %s' % encoded_signature, level=6)
        return encoded_signature

    def verify(self, toverify_in, encoded_signature_in):
        """Sign a string."""
        self.md5.update(toverify_in)
        toverify_md5 = self.md5.digest()

        # the binary value must be a tuple of length 1
        self.log('verify -> encoded_signature_in pformat \n%s' % pformat(encoded_signature_in), level=6)
        binary_signature_in = (base64.b64decode(encoded_signature_in))
        self.log('verify -> binary_signature_in %s' % binary_signature_in, level=6)
        signature_in_loaded = json.loads(binary_signature_in)
        self.log('verify -> signature_in_loaded pformat \n%s' % pformat(signature_in_loaded), level=6)
        result = self.public_key_object.verify(toverify_md5, signature_in_loaded)
        self.log('verify -> returning verify string with signature returns "%s"' % result)
        return result

    def get_pub_key(self):
        """Return The public key."""
        if self.public_key_string:
            retval = self.public_key_string, self.uuid
        else:
            retval = '', ''
        return retval

    def saveserveronclient(self, token_=None, pubkey=None, uuid_=None):
        """Save the server public on client."""
        self.keypairname = 'server_keys'
        if self.keypairname not in self.config.sections():
            self.config.add_section(self.keypairname)
        if token_:
            self.config.set(self.keypairname, 'token', token_)

        if pubkey:
            self.log('saveserveronclient pubkey %s uuid %s' % (limitlines(pubkey), uuid_))
            self.config.set(self.keypairname, 'public', pubkey)
            self.config.set(self.keypairname, 'uuid', uuid_)

        if token_ or pubkey:
            # write the new token to config file
            self.__writeconfig()

    def saveclientonserver(self, token_=None):
        """Save the client public key on server."""
        if self.keypairname not in self.config.sections():
            self.config.add_section(self.keypairname)
        if token_:
            self.config.set(self.keypairname, 'token', token_)
            self.config.set(self.keypairname, 'tokentime', datetime.now().strftime(TMEFMT))

        if self.public_key_string:
            self.config.set(self.keypairname, 'public', self.public_key_string)
            self.config.set(self.keypairname, 'uuid', self.uuid)

        if token_ or self.public_key_string:
            # write the new token to config file
            self.__writeconfig()

    @property
    def token(self):
        """Get a token for the client."""
        token_ = self.config.safe_get(self.keypairname, 'token')
        self.log('token property %s' % (token_))
        return token_

    @property
    def tokentime(self):
        """Get a token for the client."""
        token_ = self.config.safe_get(self.keypairname, 'tokentime')
        self.log('token expire time %s' % (token_))
        return token_

    def gentoken(self):
        """Generate a random token to save on sever, pass with password to client."""
        token_ = self.randstring(128)

        if self.keypairname not in self.config.sections():
            self.config.add_section(self.keypairname)

        # write the new token to config file
        self.config.set(self.keypairname, 'token', token_)
        self.__writeconfig()
        return token_

    @classmethod
    def randstring(cls, bytecount):
        """Classmethod to generate some random strings."""
        return base64.b64encode(Random.get_random_bytes(bytecount))

    def log(self, message, level=5):
        """Logg, control output here."""
        log_fv = open(self.logfile, 'a')
        show = "Keypair   -> keyname %s -> %s\n" % (self.keypairname, message)
        log_fv.write(show)
        log_fv.close()
        if self.showlog and level > 5:
            print(show)
