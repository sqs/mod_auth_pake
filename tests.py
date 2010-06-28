import unittest, urllib2
from urllib2 import Request
from http_tcpcrypt_auth import tcpcrypt_get_sid, TcpcryptAuthHandler


class TestTcpcryptAuthHandler(unittest.TestCase):

    def assertResponse(self, req, exp_status=200):
        expects_error = (exp_status >= 400)
        try:
            res = self.opener.open(req)
            if expects_error:
                raise AssertionError("expected response error (%d), got %d" % \
                                         (exp_status, res.code))
        except urllib2.HTTPError as e:
            if e.code != exp_status:
                s = []
                s.append("\n--------------------------------\nREQ\n")
                s.append("\n".join(': '.join(kv) for kv in req.unredirected_hdrs.items()))
                s.append("\nRES (%d: %s)" % (e.code, getattr(e, 'msg', None)))
                if hasattr(e, 'read'):
                    s.append(e.read())
                if hasattr(e, 'hdrs'):
                    s.append(repr(e.hdrs))
                raise AssertionError("expected response %d, got %d:\n%s" % \
                                         (exp_status, e.code, "\n".join(s)))
    
    def setUp(self):
        self.opener = urllib2.build_opener()
        self.handler = TcpcryptAuthHandler()
        self.opener.add_handler(self.handler)

    def test_authenticates_once(self):
        req = Request('http://localhost:8080/protected/')
        self.handler.add_password('protected area',
                                  'http://localhost:8080/protected/',
                                  'jsmith', 'jsmith')
        self.assertResponse(req, 200)

    def test_authentication_persists(self):
        req = Request('http://localhost:8080/protected/')
        self.handler.add_password('protected area',
                                  'http://localhost:8080/protected/',
                                  'jsmith', 'jsmith')
        self.assertResponse(req, 200)
        self.assertResponse(req, 200)

    def test_fails_authentication_no_credentials(self):
        req = Request('http://localhost:8080/protected/')
        self.assertResponse(req, 401)

    def test_fails_authentication_wrong_password(self):
        req = Request('http://localhost:8080/protected/')
        self.handler.add_password('protected area',
                                  'http://localhost:8080/protected/',
                                  'jsmith', 'badpw')
        self.assertResponse(req, 401)
    
    def test_fails_authentication_wrong_realm(self):
        req = Request('http://localhost:8080/protected/')
        self.handler.add_password('badrealm',
                                  'http://localhost:8080/protected/',
                                  'jsmith', 'jsmith')
        self.assertResponse(req, 401)

    def test_fails_authentication_wrong_username(self):
        req = Request('http://localhost:8080/protected/')
        self.handler.add_password('protected area',
                                  'http://localhost:8080/protected/',
                                  'baduser', 'jsmith')
        self.assertResponse(req, 401)
       
       
if __name__ == "__main__":
    unittest.main()
    
