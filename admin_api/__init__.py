"""An api to interact with powerdnsadmin to make changes scriptable."""
# pylint: disable=E0401
import hashlib
import json
import re
import sys
import urlparse
from ConfigParser import RawConfigParser
import requests

TIMEOUT = 10


def auth_from_url(url):
    """Are there credentials in the url."""
    auth = None
    parsed_url = urlparse.urlparse(url).netloc
    if '@' in parsed_url:
        auth = parsed_url.split('@')[0].split(':')
        auth = requests.auth.HTTPBasicAuth(auth[0], auth[1])
    return auth


def build_rrset(name=None, ipaddr=None, type_='A', ttl=86400, disabled=False):
    """Helper method for buidling and rrset dictionary."""
    rrset = {"name": "%s" % (name),
             "type": "%s" % (type_),
             "ttl": "%s" % (ttl),
             "changetype": "REPLACE",
             "records": [{
                 "content": "%s" % (ipaddr),
                 "disabled": disabled, }]}
    return rrset


def fetch_remote(remote_url, method='GET', data=None, accept=None, params=None, timeout=None, headers=None):
    # pylint: disable=R0913
    """Fetch from the remote."""
    if data is not None and not isinstance(data, str):
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

    res = requests.request(method, remote_url, headers=headers, verify=verify, auth=auth_from_url(remote_url),
                           timeout=timeout, data=data, params=params, )
    try:
        if res.status_code not in (200, 400, 422):
            res.raise_for_status()
    except Exception as err:
        raise RuntimeError("While fetching " + remote_url + ": " + str(err))

    return res


def fetch_json(remote_url, method='GET', data=None, params=None, headers=None):
    """Fetch wrapper for jason data."""
    res = fetch_remote(remote_url, method=method, data=data, params=params, headers=headers,
                       accept='application/json; q=1')

    if method == "DELETE":
        return True

    if res.status_code == 204:
        return {}

    try:
        assert 'json' in res.headers['content-type']
    except Exception as err:
        # , None, sys.exc_info()[2]
        raise Exception("While fetching " + remote_url + ": " + str(err))

    # don't use r.json here, as it will read from r.text, which will trigger
    # content encoding auto-detection in almost all cases, WHICH IS EXTREMELY
    # SLOOOOOOOOOOOOOOOOOOOOOOW. just don't.
    data = None
    try:
        data = json.loads(res.content)
    except UnicodeDecodeError:
        data = json.loads(res.content, 'iso-8859-1')
    return data


def display_record_name(data):
    """Display a record helper function."""
    record_name, domain_name = data
    if record_name == domain_name:
        retval = '@'
    else:
        retval = record_name.replace('.' + domain_name, '')
    return retval


class ApiParser(RawConfigParser):
    """A class to inherit from RawConfigParser.

    Built to have safe methods to get values
    So that the config file can not have the value and there will be a default
    """

    def safe_get(self, section, option, default=None):
        """Safe Get Method."""
        retval = default
        if self.has_option(section, option):
            retval = self.get(section, option)
        return retval

    def safe_getboolean(self, section, option, default=False):
        """Safe Get a boolean value Method."""
        retval = default
        if self.has_option(section, option):
            retval = self.getboolean(section, option)
        return retval
