#!/usr/bin/env python
import web

urls = (
    '/', 'index',
    '/signup', 'signup',
    '/login', 'login',
    '/~([a-zA-Z\d_@.-]+)', 'user',
)

app = web.application(urls, globals())

class index:
    def GET(self):
        if web.ctx.user:
            return "<h1>Home</h1>Hello, <a href='/~%s'>%s</a>." % \
                   (web.ctx.user, web.ctx.user)
        else:
            return "<h1>Home</h1><p>You're not logged in.</p>"

class signup:
    def POST(self):
        pass

class user:
    def GET(self, username):
        if username not in web.ctx.all_users:
            web.ctx.status = '404 Not Found'
            return "<h1>User '%s' not found</h1>" % username
        if username == web.ctx.user:
            return "<h1>Your profile</h1>" \
                   "<p>Your name: %s<br>Your email: %s@scs.stanford.edu</p>" % \
                   (username, username)
        elif web.ctx.user:
            return "<h1>%s's private profile</h1>" \
                   "<p>Name: %s<br>Email: %s@scs.stanford.edu</p>" % \
                   (username, username, username)
        else:
            return "<h1>%s's public profile</h1><p>Name: %s</p>" % \
                   (username, username)

def check_auth(handle):
    web.ctx.all_users = [p[0] for p in map(str.split, open('.htpake').readlines())]
    
    if web.ctx.env.get('REMOTE_USER'):
        user = web.ctx.env['REMOTE_USER']
        web.header('X-Account-Management-Status',
                   'active; name=%s; id=%s' % (user, user))
        web.ctx.user = user
    else:
        web.header('X-Account-Management-Status', 'none')
        web.ctx.user = None

    nav = "<p><a href='/'>Home</a> - Users: %s</p>" % \
        ' '.join(["<a href='/~%s'>%s</a>" % (u,u) for u in web.ctx.all_users])
    if web.ctx.user:
        footer = "<hr><p>Logged in as <a href='/~%s'>%s</a>.</p>%s" % \
            (web.ctx.user, web.ctx.user, nav)
    else:
        footer = "<hr><p>Not logged in.</p>%s" % nav
        
    return handle() + footer
app.add_processor(check_auth)
    
if __name__ == "__main__":
    app.run()
