"""This is a class and a script to api to PowerDnsAdmin."""

# pylint: disable=E0401
import base64
import sys
import os
from getpass import getpass
from pprint import pformat

from admin_api import fetch_json
from admin_api import ApiParser
from admin_api.crypt import Keypair, limitlines


class Clientapi(object):
    """Api Client Class."""

    def __init__(self):
        """Initialze the Clientapi class."""
        self.baseurl = 'http://localhost:9393'
        
        self.showlog = True

        oneup = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.logfile = '%s/afile.log' % oneup
        log_fv = open(self.logfile, 'w')
        log_fv.write('')
        log_fv.close()
        self.log("Clientapi log file is %s" % (self.logfile), level=5)

        configfile = '%s/api.cfg' % (oneup)
        config = ApiParser()
        config.read(configfile)
        self.username = config.safe_get('userinfo', 'username')
        #self.baseurl = 'http://localhost:9393'
        self.baseurl = config.safe_get('serverinfo', 'baseurl')

        self.clientkeypair = Keypair(username='mykeys', showlog=True, isclient=True)
        pubkey, uuid = self.clientkeypair.get_pub_key()
        # self.log('__init__ pub %s uuid %s' % (limitlines(pubkey), uuid))
        self.pubkey_b64 = base64.b64encode(pubkey)
        self.uuid_client_b64 = base64.b64encode(uuid)

        self.serverkeypair = Keypair(checkexists=True, showlog=True, isclient=True)
        self.log('self.serverkeypair on client exists is %s' % (self.serverkeypair.exists))

        self.confirm_key_exchange()
        if self.serverkeypair.exists:
            self.confirm_token()

    def baseheaders(self, pubkey=True):
        """The headers have some relatively consistent properties."""
        headers = {}
        headers['X-API-User'] = self.username
        if pubkey:
            headers['X-API-Pubkey'] = self.pubkey_b64
            headers['X-API-clientuuid'] = self.uuid_client_b64
        return headers

    def checkkeys(self):
        """Exchange Keys with server."""
        headers = self.baseheaders(pubkey=True)
        self.log("Clientapi checkkeys exchangekeys sending headers pprint follows")
        spubkey, suuid = self.serverkeypair.get_pub_key()
        self.log('checkkeys server pub %s uuid %s' % (limitlines(spubkey), suuid))
        spubkey_b64 = base64.b64encode(spubkey)
        if suuid:
            suuid_server_b64 = base64.b64encode(suuid)
            headers['X-API-Serveruuid'] = suuid_server_b64
        else:
            headers['X-API-Serveruuid'] = ''
        headers['X-API-Serverpubkey'] = spubkey_b64

        url = '%s/checkkeys' % (self.baseurl)
        jdata = fetch_json(url, headers=headers, data=None, method='POST')
        self.log("Clientapi exchangekeys jdata returned : %s" % (jdata))

        if 'status' in jdata:
            status = jdata['status']
            self.log('checkkeys status is %s' % (status))
            if status == 'serverkey':
                # jdata['server_pubkey'] is the base64 version of the public key
                server_pubkey = base64.b64decode(jdata['server_pubkey'])
                server_uuid = base64.b64decode(jdata['server_uuid'])
                self.log('exchangekeys server_pubkey is "%s" server_uuid is "%s"' %
                         (limitlines(server_pubkey), server_uuid))
                self.serverkeypair.initafter(server_pubkey, server_uuid)
                retval = False
            elif status == 'ok':
                retval = True
            else:
                retval = False
        return retval

    def checktoken(self):
        """Check the token on server."""
        headers = self.baseheaders(pubkey=False)
        self.log("Clientapi checktoken encrypting token %s" % (self.serverkeypair.token))
        retval = False
        if self.serverkeypair.token:
            encryptedtoken = self.serverkeypair.encrypt(self.serverkeypair.token)
            headers['X-API-Key'] = encryptedtoken
            headers['X-API-Signature'] = self.clientkeypair.sign(encryptedtoken)
            self.log(headers)

            url = '%s/token_check' % (self.baseurl)
            jdata = fetch_json(url, headers=headers, data=None, method='POST')
            self.log(pformat(jdata, indent=4))

            if 'status' in jdata:
                status = jdata['status']
                self.log('status is %s' % (status))
                if status == 'Token Success':
                    if 'encryptedtoken' in jdata:
                        self.savetoken(jdata['encryptedtoken'])
                    retval = True
        self.log("checktoken returning %s" % retval)
        return retval

    def savetoken(self, encryptedtoken):
        """Save the Token"""
        self.log('gettoken -> encryptedtoken is %s' % (encryptedtoken))
        # self.clientkeypair.showlog = True
        token_ = self.clientkeypair.decrypt(encryptedtoken)
        self.log('gettoken -> token is %s' % (token_))
        self.serverkeypair.saveserveronclient(token_=token_)

    def gettoken(self, passwd):
        """get a token from server."""
        headers = self.baseheaders(pubkey=False)
        self.log("Clientapi gettoken sending headers, pprint follows")
        encryptedpassword = self.serverkeypair.encrypt(passwd)
        headers['X-API-Password'] = encryptedpassword
        self.log(pformat(headers, indent=4))

        url = '%s/token_request' % (self.baseurl)
        jdata = fetch_json(url, headers=headers, data=None, method='POST')
        self.log(pformat(jdata, indent=4))

        retval = False
        if 'status' in jdata:
            status = jdata['status']
            self.log('status is %s' % (status))
            if status == 'Password Success':
                self.savetoken(jdata['encryptedtoken'])
                retval = True
        return retval

    def perform_add(self, name=None, ipaddr=None, ttl=None):
        """Perform add, this is the whole purpos, the rest is to authenticate the api script."""
        if name and ipaddr:
            headers = self.baseheaders(pubkey=False)

            if self.serverkeypair.token:
                encryptedtoken = self.serverkeypair.encrypt(self.serverkeypair.token)
                headers['X-API-Key'] = encryptedtoken
                headers['X-API-Signature'] = self.clientkeypair.sign(encryptedtoken)

            self.log("sending headers, pprint follows", level=5)
            self.log(pformat(headers, indent=4), level=5)

            data = {'name': name,
                    'ipaddr': ipaddr}
            if ttl:
                data['ttl'] = ttl

            url = '%s/addhost' % (self.baseurl)
            jdata = fetch_json(url, headers=headers, data=data, method='POST')

            self.log("jdata from server, pprint follows", level=5)
            self.log(pformat(jdata, indent=4), level=10)
        else:
            self.log("Need a name and an ip address", level=5)

    def fixrev(self, hostname=None, revname=None):
        """Perform add, this is the whole purpos, the rest is to authenticate the api script."""
        if hostname and revname:
            headers = self.baseheaders(pubkey=False)

            if self.serverkeypair.token:
                encryptedtoken = self.serverkeypair.encrypt(self.serverkeypair.token)
                headers['X-API-Key'] = encryptedtoken
                headers['X-API-Signature'] = self.clientkeypair.sign(encryptedtoken)

            self.log("sending headers, pprint follows", level=5)
            self.log(pformat(headers, indent=4), level=5)

            data = {'hostname': hostname,
                    'revname': revname}
            url = '%s/fixrev' % (self.baseurl)
            jdata = fetch_json(url, headers=headers, data=data, method='POST')

            self.log("jdata from server, pprint follows", level=5)
            self.log(pformat(jdata, indent=4), level=10)
        else:
            self.log("Need a hostname and an revname", level=5)

    def log(self, message, level=5):
        """Logg, control output here."""
        show = "Clientapi -> %s" % (message)
        log_fv = open(self.logfile, 'a')
        log_fv.write('%s\n' % show)
        log_fv.close()
        if self.showlog and level > 5:
            print(show)

    def confirm_token(self):
        """Use the tools to confirm the token is ready to use."""
        self.log("########## Exchange done exists is now %s, CHECKING TOKEN ###############################" %
                 (self.serverkeypair.exists))
        # Start the outer loop checking password
        outercounter = 0
        outerdone = False
        while not outerdone:
            self.log("Looping till the token is valid : ", level=10)
            if self.checktoken():
                outerdone = True
            else:
                # start the inner loop checkingpassword
                innercounter = 0
                innerdone = False
                while not innerdone:
                    self.log("You want a token, the server needs your password : ", level=10)
                    password = getpass()
                    if self.gettoken(password):
                        innerdone = True
                    innercounter += 1
                    if innercounter > 5:
                        self.log("Thats alot of password failures", level=10)
                        sys.exit()
            outercounter += 1
            if outercounter > 3:
                self.log("outercounter greater than", level=10)
                sys.exit()

    def confirm_key_exchange(self):
        """Use other methods in loop to confirm the key exchange occurs correctly."""
        counter = 0
        done = False
        while not done:
            self.log("########## checkkeys counter is %s ########################" % (counter))
            if self.checkkeys():
                done = True
            if counter > 3:
                done = True
                self.log("########## checkkeys Exiting Key Exchange issue" % (counter))
                sys.exit()
            counter += 1
        self.log("Keys exchanged %s" % self.serverkeypair.exists)
