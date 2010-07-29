#!/usr/bin/env python
import web

USER_FILE_PATH = '.htpake'

urls = (
    '/', 'index',
    '/signup', 'signup',
    '/login', 'login',
    '/~([a-zA-Z\d]+)', 'user',
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
    hex_re = web.form.regexp(r'^[A-F\d]{20,500}$', 'must be uppercase hex')
    form = web.form.Form(
        web.form.Textbox('username', web.form.notnull,
                         web.form.regexp(r'^[a-zA-Z\d]{3,20}$',
                                         'must be alphanum{3,20}')),
        web.form.Textarea('pi_0', web.form.notnull, hex_re),
        web.form.Textarea('L', web.form.notnull, hex_re),
        web.form.Button('Create account')
    )
    
    def GET(self, f = None):
        f = f or self.form()
        return "<h1>Sign up</h1>" \
               "<p>You better trust this connection!</p>" \
               "<form method=post>%s</form>" % \
               f.render()
        
    def POST(self):
        f = self.form()
        if not f.validates():
            return self.GET(f)
        # TODO(sqs): check username uniqueness
        # TODO(sqs): obviously not safe if two processes try to access at same time
        userfile = open(USER_FILE_PATH, 'ab')
        userfile.write("%s %s %s\n" % (f.d.username, f.d.pi_0, f.d.L))
        userfile.close()
        return "<h1>Sign up: success</h1><table>" \
               "<tr><th>username</th><td>%s</td></tr>" \
               "<tr><th>pi_0</th><td><tt>%s</tt></td></tr>" \
               "<tr><th>L</th><td><tt>%s</tt></td></tr></table>" % \
               (f.d.username, f.d.pi_0, f.d.L)

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
    web.ctx.all_users = [p[0] for p in \
                             map(str.split, open(USER_FILE_PATH).readlines())]
    
    if web.ctx.env.get('REMOTE_USER'):
        user = web.ctx.env['REMOTE_USER']
        web.header('X-Account-Management-Status',
                   'active; name=%s; id=%s' % (user, user))
        web.ctx.user = user
    else:
        web.header('X-Account-Management-Status', 'none')
        web.ctx.user = None

    nav = "<p><a href='/'>Home</a> - <a href='/signup'>Sign up</a> - " \
          "Users: %s</p>" % \
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
