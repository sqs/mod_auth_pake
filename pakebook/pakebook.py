#!/usr/bin/env python
import web

urls = (
    '/', 'index',
    '/signup', 'signup',
    '/login', 'login',
)

app = web.application(urls, globals())

class index:
    def GET(self):
        if web.ctx.user:
            return "Hello, %s." % web.ctx.user
        else:
            return "Not logged in."

class signup:
    def POST(self):
        pass

def check_auth(handle):
    if 'REMOTE_USER' in web.ctx.env:
        user = web.ctx.env['REMOTE_USER']
        web.header('X-Account-Management-Status',
                   'active; name=%s; id=%s' % (user, user))
        web.ctx.user = user
    else:
        web.header('X-Account-Management-Status', 'none')
        web.ctx.user = None
    return handle()
app.add_processor(check_auth)
    
if __name__ == "__main__":
    app.run()
