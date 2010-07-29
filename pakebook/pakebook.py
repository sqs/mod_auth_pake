#!/usr/bin/env python
import web

urls = (
    '/', 'index',
)

app = web.application(urls, globals())

class index:
    def GET(self):
        return "Hello, world"

def check_auth(handle):
    if 'REMOTE_USER' in web.ctx.env:
        user = web.ctx.env['REMOTE_USER']
        web.header('X-Account-Management-Status',
                   'active; name=%s; id=%s' % (user, user))
    else:
        web.header('X-Account-Management-Status', 'none')
    handle()
app.add_processor(check_auth)
    
if __name__ == "__main__":
    app.run()
