import os
import base64
import xmlrpc.client
import urllib.request, urllib.error, urllib.parse
import http.cookiejar

import pickle

from tempfile import mkstemp
from openipam.utilities import error


class PickleCookieJar(http.cookiejar.CookieJar):
    def __init__(self, *args):
        self._initargs = args
        http.cookiejar.CookieJar.__init__(self, *args)

    def __getinitargs__(self):
        return self._initargs

    def __getstate__(self):
        cookie_list = []
        for cookie in self:
            cookie_list.append(pickle.dumps(cookie))
        return cookie_list

    def __setstate__(self, cookie_list):
        for cookie_str in cookie_list:
            self.set_cookie(pickle.loads(cookie_str))


class CookieAuthXMLRPCSafeTransport(xmlrpc.client.Transport):
    """xmlrpclib.Transport that sends HTTP(S) Authentication"""

    user_agent = "*py*"
    credentials = ()
    cj = None
    transport = "https"
    ssl = True
    _extra_headers = None

    def __init__(self, cookiejar=None, ssl=True, use_datetime=True):
        xmlrpc.client.Transport.__init__(self, use_datetime=use_datetime)
        if not ssl:
            self.ssl = False
            self.transport = "http"

        if cookiejar:
            self.cj = cookiejar
        else:
            self.cj = PickleCookieJar()

    def make_connection(self, host):
        # create a HTTPS connection object from a host descriptor
        # host may be a string, or a (host, x509-dict) tuple
        if not self.ssl:
            return xmlrpc.client.Transport.make_connection(self, host)
        import http.client

        host, extra_headers, x509 = self.get_host_info(host)
        try:
            HTTPS = http.client.HTTPS
        except AttributeError:
            raise NotImplementedError("your version of httplib doesn't support HTTPS")
        else:
            return HTTPS(host, None, **(x509 or {}))

    def get_cookiejar(self):
        return self.cj

    def send_basic_auth(self, connection):
        """Include HTTP Basic Authentication data in a header"""

        auth = base64.encodestring("%s:%s" % self.credentials).strip()
        auth = "Basic %s" % (auth,)
        connection.putheader("Authorization", auth)

    def send_cookie_auth(self, connection):
        """Include Cookie Authentication data in a header"""
        for cookie in self.cj:
            if cookie.name == "session_id":
                uuidstr = cookie.value
            connection.putheader("Cookie", cookie.name + "=" + cookie.value)

    ## override the send_host hook to also send authentication info
    def send_host(self, connection, host):
        xmlrpc.client.Transport.send_host(self, connection, host)
        if self.cj:
            self.send_cookie_auth(connection)

    #               elif self.credentials != ():
    #                       self.send_basic_auth(connection)

    def request(self, host, handler, request_body, verbose=0):
        # dummy request class for extracting cookies
        class CookieRequest(urllib.request.Request):
            pass

        # dummy response class for extracting cookies
        class CookieResponse:
            def __init__(self, headers):
                self.headers = headers

            def info(self):
                return self.headers

        crequest = CookieRequest("%s://%s/" % (self.transport, host))

        # issue XML-RPC request
        h = self.make_connection(host)
        if verbose:
            h.set_debuglevel(1)

        self.send_request(h, handler, request_body)
        self.send_host(h, host)
        self.send_user_agent(h)

        # creating a cookie jar for my cookies
        if self.cj == None:
            raise error.NotFound("Lost self.cj")

        self.send_content(h, request_body)

        errcode, errmsg, headers = h.getreply()

        cresponse = CookieResponse(headers)
        self.cj.extract_cookies(cresponse, crequest)

        if errcode != 200:
            raise xmlrpc.client.ProtocolError(host + handler, errcode, errmsg, headers)

        self.verbose = verbose

        return self.parse_response(h.getfile())
