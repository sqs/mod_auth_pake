import urllib2

class TcpcryptAuthHandler(urllib2.BaseHandler):

    def http_error_auth_reqed(authreq, host, req, headers):
        print "asdf"

if __name__ == "__main__":
    req = urllib2.Request('http://localhost:8080/protected/')
    opener = urllib2.build_opener()
    opener.add_handler(TcpcryptAuthHandler())
    try:
        res = opener.open(req)
        print res.info()
    except urllib2.HTTPError as e:
        print e.code
        print e.read()
        print req.unredirected_hdrs
