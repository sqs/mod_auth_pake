import unittest, urllib2
from http_tcpcrypt_auth import tcpcrypt_get_sid, TcpcryptAuthHandler


class TestModAuthTcpcrypt(unittest.TestCase):

    def assertAuthenticates(self, req):
        try:
            res = self.opener.open(req)
        except urllib2.HTTPError as e:
            print "\n--------------------------------\n\n"
            print "REQ"
            print "\n".join(': '.join(kv) for kv in req.unredirected_hdrs.items())
            print "\nRES (%d: %s)" % (e.code, getattr(e, 'msg', None))
            if hasattr(e, 'read'):
                print e.read()
            if hasattr(e, 'hdrs'):
                print e.hdrs

    
    def setUp(self):
        self.opener = urllib2.build_opener()
        tcpcrypt_auth = TcpcryptAuthHandler()
        tcpcrypt_auth.add_password('protected area',
                                   'http://localhost:8080/protected/',
                                   'jsmith', 'jsmith')
        self.opener.add_handler(tcpcrypt_auth)

    def test_authenticates_once(self):
        req = urllib2.Request('http://localhost:8080/protected/')
        self.assertAuthenticates(req)
       
if __name__ == "__main__":
    unittest.main()
    
