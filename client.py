import urllib2, urlparse, logging, hashlib, time


logging.basicConfig(level=logging.DEBUG)


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
        host = urlparse.urlparse(req.get_full_url())[1]
        retry = self.http_error_auth_reqed('www-authenticate', host, req, headers)
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

    def get_cnonce(self, nonce):
        # taken from urllib2
        # The cnonce-value is an opaque
        # quoted string value provided by the client and used by both client
        # and server to avoid chosen plaintext attacks, to provide mutual
        # authentication, and to provide some message integrity protection.
        # This isn't a fabulous effort, but it's probably Good Enough.
        dig = hashlib.sha1("%s:%s:%s:%s" % (self.nonce_count, nonce, time.ctime(),
                                            urllib2.randombytes(8))).hexdigest()
        return dig[:16]

    def get_authorization(self, req, chal):
        # taken from urllib2
        try:
            realm = chal['realm']
            nonce = chal['nonce']
            qop = chal.get('qop')
            algorithm = chal.get('algorithm', 'MD5')
            # mod_digest doesn't send an opaque, even though it isn't
            # supposed to be optional
            opaque = chal.get('opaque', None)
        except KeyError:
            return None

        H, KD = self.get_algorithm_impls(algorithm)
        if H is None:
            return None

        user, pw = self.passwd.find_user_password(realm, req.get_full_url())
        if user is None:
            self.logger.debug("get_authorization: no user for realm '%s'" % realm)
            return None

        A1 = "%s:%s:%s" % (user, realm, pw)
        A2 = "%s:%s" % (req.get_method(), req.get_selector())

        if qop == 'auth':
            if nonce == self.last_nonce:
                self.nonce_count += 1
            else:
                self.nonce_count = 1
                self.last_nonce = nonce

            ncvalue = '%08x' % self.nonce_count
            cnonce = self.get_cnonce(nonce)
            noncebit = "%s:%s:%s:%s:%s" % (nonce, ncvalue, cnonce, qop, H(A2))
            respdig = KD(H(A1), noncebit)
        elif qop is None:
            respdig = KD(H(A1), "%s:%s" % (nonce, H(A2)))
        else:
            # XXX handle auth-int
            raise URLError("qop '%s' is not supported." % qop)

        base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
               'response="%s"' % (user, realm, nonce, req.get_selector(), respdig)
        if opaque:
            base += ', opaque="%s"' % opaque
        base += ', algorithm="%s"' % algorithm
        if qop:
            base += ', qop=auth, nc=%s, cnonce="%s"' % (ncvalue, cnonce)
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


if __name__ == "__main__":
    req = urllib2.Request('http://localhost:8080/protected/')
    opener = urllib2.build_opener()
    tcpcrypt_auth = TcpcryptAuthHandler()
    tcpcrypt_auth.add_password('protected area',
                               'http://localhost:8080/protected/',
                               'jsmith', 'jsmith')
    opener.add_handler(tcpcrypt_auth)
    try:
        res = opener.open(req)
        print "\n--------------------------------\n\n", res.info()
        print res.read()
    except urllib2.HTTPError as e:
        print "\n--------------------------------\n\n"
        print e.code
        print e.read()
        print req.unredirected_hdrs
