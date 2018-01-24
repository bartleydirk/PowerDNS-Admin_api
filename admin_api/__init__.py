import re
import sys
import json
import requests
import urlparse
import hashlib
from ConfigParser import RawConfigParser



#from app import app
#from distutils.version import StrictVersion

#if 'TIMEOUT' in app.config.keys():
#    TIMEOUT = app.config['TIMEOUT']
#else:
TIMEOUT = 10

def auth_from_url(url):
    auth = None
    parsed_url = urlparse.urlparse(url).netloc
    if '@' in parsed_url:
        auth = parsed_url.split('@')[0].split(':')
        auth = requests.auth.HTTPBasicAuth(auth[0], auth[1])
    return auth


def build_rrset(name=None, ipaddr=None, type_='A', ttl=86400, disabled=False):
    rrset = {"name": "%s" % (name),
             "type": "%s" % (type_),
             "ttl": "%s" % (ttl),
             "changetype": "REPLACE",
             "records": [{
                 "content": "%s" % (ipaddr),
                 "disabled": disabled, }]}
    return rrset


def fetch_remote(remote_url, method='GET', data=None, accept=None, params=None, timeout=None, headers=None):
    if data is not None and type(data) != str:
        data = json.dumps(data)

    if timeout is None:
        timeout = TIMEOUT

    verify = False

    our_headers = {
        'user-agent': 'powerdnsadmin/0',
        'pragma': 'no-cache',
        'cache-control': 'no-cache'
    }
    if accept is not None:
        our_headers['accept'] = accept
    if headers is not None:
        our_headers.update(headers)

    r = requests.request(
        method,
        remote_url,
        headers=headers,
        verify=verify,
        auth=auth_from_url(remote_url),
        timeout=timeout,
        data=data,
        params=params
        )
    try:
        if r.status_code not in (200, 400, 422):
            r.raise_for_status()
    except Exception as e:
        raise RuntimeError("While fetching " + remote_url + ": " + str(e)), None, sys.exc_info()[2]

    return r


def fetch_json(remote_url, method='GET', data=None, params=None, headers=None):
    r = fetch_remote(remote_url, method=method, data=data, params=params, headers=headers, accept='application/json; q=1')

    if method == "DELETE":
        return True

    if r.status_code == 204:
        return {}

    try:
        assert('json' in r.headers['content-type'])
    except Exception as e:
        raise Exception("While fetching " + remote_url + ": " + str(e)), None, sys.exc_info()[2]

    # don't use r.json here, as it will read from r.text, which will trigger
    # content encoding auto-detection in almost all cases, WHICH IS EXTREMELY
    # SLOOOOOOOOOOOOOOOOOOOOOOW. just don't.
    data = None
    try:
        data = json.loads(r.content)
    except UnicodeDecodeError:
        data = json.loads(r.content, 'iso-8859-1')
    return data


def display_record_name(data):
    record_name, domain_name = data
    if record_name == domain_name:
        return '@'
    else:
        return record_name.replace('.'+domain_name, '')


class ApiParser(RawConfigParser):
    """
    A class to inherit from RawConfigParser and have safe methods to get values
    So that the config file can not have the value and there will be a default
    """
    def safe_get(self, section, option, default=None):
        """ Safe Get Method """
        if self.has_option(section, option):
            return self.get(section, option)
        else:
            return default

    def safe_getboolean(self, section, option, default=False):
        """ Safe Get a boolean value Method """
        if self.has_option(section, option):
            return self.getboolean(section, option)
        else:
            return default
