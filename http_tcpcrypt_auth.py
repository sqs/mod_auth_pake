import urllib2, urlparse, logging, hashlib, time


logging.basicConfig(level=logging.DEBUG)

def tcpcrypt_get_sid():
    return 1122334455

class TcpcryptAuthHandler(urllib2.BaseHandler):

    """
    Handles HTTP 401 error responses by performing tcpcrypt
    authentication with the server.
    """

    # Proxies use the Proxy-Authorization header, but this only handles the simpler
    # case without proxies.
    auth_header = 'Authorization'
    
    def __init__(self, passwd=None):
        self.logger = logging.getLogger('TcpcryptAuthHandler')

        # taken from urllib2.py
        if passwd is None:
            passwd = urllib2.HTTPPasswordMgr()
        self.passwd = passwd
        self.add_password = self.passwd.add_password
        self.retried = 0
        self.nonce_count = 0
        self.last_nonce = None

    def reset_retry_count(self):
        self.retried = 0

    def http_error_401(self, authreq, fp, code, msg, headers):
        # taken from urllib2.py
        host = urlparse.urlparse(authreq.get_full_url())[1]
        retry = self.http_error_auth_reqed('www-authenticate', host, authreq, headers)
        self.reset_retry_count()
        return retry

    def http_error_auth_reqed(self, auth_header, host, req, headers):
        # taken from urllib2.py
        authreq = headers.get(auth_header, None)
        if self.retried >= 2:
            # Don't fail endlessly.
            raise urllib2.HTTPError(req.get_full_url(), 401, "tcpcrypt auth failed",
                                    headers, None)
        else:
            self.retried += 1
        if authreq:
            scheme = authreq.split()[0]
            self.logger.debug("http_error_auth_reqed: %s" % authreq)
            if scheme.lower() == 'tcpcrypt':
                return self.retry_http_digest_auth(req, authreq)

    def retry_http_digest_auth(self, req, auth):
        # taken from urllib2
        token, challenge = auth.split(' ', 1)
        chal = urllib2.parse_keqv_list(urllib2.parse_http_list(challenge))
        auth = self.get_authorization(req, chal)
        if auth:
            auth_val = 'Tcpcrypt %s' % auth
            self.logger.debug("retry_http_digest_auth: made auth header: %s" \
                              % auth_val)

            # If the last request had the same auth headers, we've already
            # tried and failed authenticating with these credentials, so don't
            # resend this auth attempt.
            if req.headers.get(self.auth_header, None) == auth_val:
                self.logger.debug("retry_http_digest_auth: already " \
                                  "attempted auth with this header;" \
                                  " failing")
                return None
            
            req.add_unredirected_header(self.auth_header, auth_val)
            resp = self.parent.open(req, timeout=req.timeout)
            return resp

    def get_authorization(self, req, chal):
        # taken from urllib2
        try:
            realm = chal['realm']
            nonce = chal['nonce']
            algorithm = chal.get('algorithm', 'MD5')
        except KeyError:
            return None

        H, KD = self.get_algorithm_impls(algorithm)
        if H is None:
            return None

        user, pw = self.passwd.find_user_password(realm, req.get_full_url())
        if user is None:
            self.logger.debug("get_authorization: no user for realm '%s'" % realm)
            return None

        A1 = "%s:%s:%s:%lx" % (nonce, realm, pw, tcpcrypt_get_sid())
        A2 = "%s:%s" % (req.get_method(), req.get_selector())

        respdig = H(A1)

        base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
               'response="%s"' % (user, realm, nonce, req.get_selector(), respdig)
        base += ', algorithm="%s"' % algorithm
        return base

    def get_algorithm_impls(self, algorithm):
        # from urllib2
        # algorithm should be case sensitive according to RFC2617
        algorithm = algorithm.upper()
        # lambdas assume digest modules are imported at the top level
        if algorithm == 'MD5':
            H = lambda x: hashlib.md5(x).hexdigest()
        elif algorithm == 'SHA':
            H = lambda x: hashlib.sha1(x).hexdigest()
        KD = lambda s, d: H("%s:%s" % (s, d))
        return H, KD
