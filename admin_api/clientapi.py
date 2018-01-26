"""This is a class and a script to api to PowerDnsAdmin."""

# pylint: disable=E0401
import base64
import sys
from getpass import getpass
from pprint import pprint

from admin_api import fetch_json, build_rrset
from admin_api.crypt import Keypair, limitlines


class Clientapi(object):
    """Api Client Class."""

    def __init__(self):
        """Initialze the Clientapi class."""
        self.baseurl = 'http://localhost:9393'
        self.username = 'dbartley'
        self.showlog = False

        self.clientkeypair = Keypair(username='mykeys', showlog=False, isclient=True)
        pubkey, uuid = self.clientkeypair.get_pub_key()
        # self.log('__init__ pub %s uuid %s' % (limitlines(pubkey), uuid))
        self.pubkey_b64 = base64.b64encode(pubkey)
        self.uuid_client_b64 = base64.b64encode(uuid)

        self.serverkeypair = Keypair(checkexists=True, showlog=False, isclient=True)
        self.log('self.serverkeypair on client exists is %s' % (self.serverkeypair.exists))

        self.confirm_exchange()
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
        suuid_server_b64 = base64.b64encode(suuid)
        headers['X-API-Serverpubkey'] = spubkey_b64
        headers['X-API-Serveruuid'] = suuid_server_b64

        url = '%s/checkkeys' % (self.baseurl)
        jdata = fetch_json(url, headers=headers, data=None, method='POST')
        self.log("Clientapi exchangekeys jdata returned : ")
        pprint(jdata)

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
        encryptedtoken = self.serverkeypair.encrypt(self.serverkeypair.token)
        retval = False
        if self.serverkeypair.token:
            headers['X-API-Key'] = encryptedtoken
            self.log(headers)

            url = '%s/token_check' % (self.baseurl)
            jdata = fetch_json(url, headers=headers, data=None, method='POST')
            pprint(jdata)

            if 'status' in jdata:
                status = jdata['status']
                self.log('status is %s' % (status))
                if status == 'Token Success':
                    retval = True
        self.log("checktoken returning %s" % retval)
        return retval

    def gettoken(self, passwd):
        """get a token from server."""
        headers = self.baseheaders(pubkey=False)
        self.log("Clientapi gettoken sending headers, pprint follows")
        encryptedpassword = self.serverkeypair.encrypt(passwd)
        headers['X-API-Password'] = encryptedpassword
        pprint(headers)

        url = '%s/token_request' % (self.baseurl)
        jdata = fetch_json(url, headers=headers, data=None, method='POST')
        pprint(jdata)

        if 'status' in jdata:
            status = jdata['status']
            self.log('status is %s' % (status))
            if status == 'Password Success':
                encryptedtoken = jdata['encryptedtoken']
                self.log('gettoken -> encryptedtoken is %s' % (encryptedtoken))
                # self.clientkeypair.showlog = True
                token_ = self.clientkeypair.decrypt(encryptedtoken)
                self.log('gettoken -> token is %s' % (token_))
                self.serverkeypair.saveserveronclient(token_=token_)

    def perform_add(self, name=None, ipaddr=None):
        """Perform add, this is the whole purpos, the rest is to authenticate the api script."""
        if name and ipaddr:
            data = []
            data.append(build_rrset(name=name, ipaddr=ipaddr))
            headers = self.baseheaders(pubkey=False)

            encryptedtoken = self.serverkeypair.encrypt(self.serverkeypair.token)
            if self.serverkeypair.token:
                headers['X-API-Key'] = encryptedtoken

            self.log("sending headers, pprint follows", level=6)
            pprint(headers)

            url = '%s/api' % (self.baseurl)
            jdata = fetch_json(url, headers=headers, data=data, method='POST')
            self.log("jdata from server, pprint follows", level=6)
            pprint(jdata)
        else:
            self.log("Need a name and an ip address", level=6)

    def log(self, message, level=5):
        """Logg, control output here."""
        if self.showlog:
            if level > 5:
                show = "Clientapi -> %s" % (message)
                print(show)

    def confirm_token(self):
        """Use the tools to confirm the token is ready to use."""
        self.log("########## Exchange done exists is now %s, CHECKING TOKEN ###############################" %
                 (self.serverkeypair.exists))
        # Start the outer loop checking password
        outercounter = 0
        outerdone = False
        while not outerdone:
            self.log("Looping till the token is valid : ")
            if self.checktoken():
                outerdone = True
            else:
                # start the inner loop checkingpassword
                innercounter = 0
                innerdone = False
                while not innerdone:
                    self.log("You want a token, the server needs your password : ")
                    password = getpass()
                    if self.gettoken(password):
                        innerdone = True
                    innercounter += 1
                    if innercounter > 5:
                        self.log("Thats alot of password failures")
                        sys.exit()
            outercounter += 1
            if outercounter > 3:
                self.log("outercounter greater than")
                sys.exit()

    def confirm_exchange(self):
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
