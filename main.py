import os
import random
from string import letters
import hashlib
import jinja2
import webapp2
from google.appengine.ext import db
import re
import hmac
import time
secret='blaaaa'


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

def render_str(template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
		
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
		
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)
		
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
		
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie','%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
		
    
def render_post(response, blog):
        response.out.write('<b>' + blog.title + '</b><br>')
        response.out.write(blog.content)

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)
	
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

	
#database to store user credentials
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

def blog_key(name = 'default'):
    return db.Key.from_path('blog', name)

#database to store blog
class Blog(db.Model):
    title=db.StringProperty(required=True)
    content=db.TextProperty(required=True)
    author=db.StringProperty(required=True)
    created=db.DateTimeProperty(auto_now_add=True)
    modified=db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(required=True)
    liked_by = db.ListProperty(str)
	
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("blog.html", a = self)
    @property
    def comments(self):
        return Comment.all().filter("blog = ", str(self.key().id()))
		
#Regular expressions to validate username,password and email id
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

#to handle signup
class Signup(Handler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            u=User.by_name(username)
            if u:
                msg="Username already used"
                self.render('signup-form.html',error_username=msg)
            else:
                u=User.register(username,password,email)
                u.put()
                self.login(u)
                self.redirect('/blog/welcome')
				
class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/blog/signup')
			
			
class Login(Handler):
    def get(self):
        self.render('login-form.html')
    def post(self):
        username=self.request.get("username")
        password=self.request.get("password")
        u=User.login(username,password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

#to handle logout
class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog/signup')

#tp populate front page		
class FrontPage(Handler):
    def get(self):
        blogs = db.GqlQuery("select * from Blog order by created desc limit 10")
        self.render('home.html', blogs = blogs)

        
class Home(Handler):
    def get(self, blog_id):
        key = db.Key.from_path('Blog', int(blog_id), parent=blog_key())
        blog = db.get(key)

        if not blog:
            self.error(404)
            return
        self.render("permalink.html", blog = blog)

		
#for like blog
class LikePost(Handler):
    def get(self, blog_id):
        if not self.user:
            self.redirect('/blog/login')
        else:
            key = db.Key.from_path('Blog', int(blog_id), parent=blog_key())
            blog = db.get(key)
            author = blog.author
            logged_user = self.user.name

            if author == logged_user or logged_user in blog.liked_by:
                msg="You cant like this post as you have already liked it or you own the post"
                self.render("error.html",error=msg)
					
            else:
                blog.likes += 1
                blog.liked_by.append(logged_user)
                blog.put()
                self.redirect("/blog/")		

#for editing the blog				
class EditPost(Handler):
    def get(self, blog_id):
        if not self.user:
            self.redirect('/blog/login')
        else:
            key = db.Key.from_path('Blog', int(blog_id), parent=blog_key())
            blog= db.get(key)
            author = blog.author
            loggedUser = self.user.name

            if author == loggedUser:
                self.render("edit.html", title=blog.title,content=blog.content)
            else:
                msg="You do not have permission to edit this post"
                self.render("error.html",error=msg)

    def post(self, blog_id):
        if not self.user:
            self.redirect("/blog/login")
        else:
            key = db.Key.from_path('Blog', int(blog_id), parent=blog_key())
            p = db.get(key)
            p.title = self.request.get('Title')
            p.content = self.request.get('Content')
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
#for deleting the blog			
class DeletePost(Handler):
    def get(self, blog_id):
        if not self.user:
            self.redirect('/blog/login')
        else:
            key = db.Key.from_path('Blog', int(blog_id), parent=blog_key())
            blog = db.get(key)
            author = blog.author
            loggedUser = self.user.name

            if author == loggedUser:
                blog.delete()
                msg="Done deleting the post"
                self.render("error.html",error=msg)
            else:
                msg="You are not authorised delete the post"
                self.render("error.html",error=msg)			

#defining the database for comments
class Comment(db.Model):
    comment = db.StringProperty(required=True)
    blog = db.StringProperty(required=True)
    author = db.StringProperty(required=True)

    @classmethod
    def render(self):
        self.render("comment.html")

#to add comments
class AddComment(Handler):
    def get(self, blog_id):
        if not self.user:
            self.redirect("/blog/login")
            return

        blog = Blog.get_by_id(int(blog_id), parent=blog_key())
        title = blog.title
        content = blog.content
        self.render("newcomment.html", title=title, content=content,username=self.user.name, pkey=blog.key())

    def post(self, blog_id):
        key = db.Key.from_path('Blog', int(blog_id), parent=blog_key())
        blog = db.get(key)
        if not blog:
            self.error(404)
            return

        if not self.user:
            self.redirect('login')

        comment = self.request.get('comment')

        if comment:
            author = self.user.name
            c = Comment(comment=comment, blog=blog_id, parent=self.user.key(), author=author)
            c.put()
            self.redirect('/blog/%s' % str(blog_id))
        else:
            error = "please provide a comment!"
            self.render("newcomment.html", blog = blog,pkey=blog.key(), error=error)
#to update comments
class UpdateComment(Handler):
    def get(self, blog_id, comment_id):
        blog = Blog.get_by_id(int(blog_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            self.render("newcomment.html", title=blog.title, content=blog.content, comment=comment.comment,pkey=blog.key())
        else:
            msg="Something went wrong"
            self.render("error.html",error=msg)

    def post(self, blog_id, comment_id):
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment.parent().key().id() == self.user.key().id():
            comment.comment = self.request.get('comment')
            comment.put()
        self.redirect('/blog/%s' % str(blog_id))

#to delete comments
class DeleteComment(Handler):
    def get(self, blog_id, comment_id):
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            comment.delete()
            self.redirect('/blog/%s' % str(blog_id))
        else:
            msg="Something went wrong"
            self.render("error.html",error=msg)

	
	

#handler for newpost page		
class Create(Handler):
    def get(self):
        if self.user:
            self.render("front.html")
        else:
            self.redirect('/blog/login')
    def post(self):
        if not self.user:
            return self.redirect('/blog/?')
        user=self.user
        title=self.request.get("title")
        content=self.request.get("content")
        author=self.user.name
        if title and content:
            a=Blog(parent=blog_key(),title=title,author=author,content=content,likes=0,liked_by=[])
            a.put()
            self.redirect('/blog/%s' % str(a.key().id()))
        else:
            error="We need both the title and the content"
            self.render("front.html",title=title,content=content,error=error)
            

app = webapp2.WSGIApplication([('/blog/([0-9]+)', Home),
                               ('/blog/([0-9]+)/comment',AddComment),
                               ('/blog/([0-9]+)/updatecomment/([0-9]+)',UpdateComment),
                               ('/blog/([0-9]+)/deletecomment/([0-9]+)',DeleteComment),
                               ('/blog/([0-9]+)/delete',DeletePost),
                               ('/blog/signup',Signup),
                               ('/blog/([0-9]+)/edit',EditPost),
                               ('/blog/([0-9]+)/like',LikePost),
                               ('/blog/?', FrontPage),
                               ('/blog/welcome',Welcome),
                               ('/blog/logout',Logout),
                               ('/blog/login',Login),
                               ('/blog/newpost', Create)], debug=True)
