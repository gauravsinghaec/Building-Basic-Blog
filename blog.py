# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import webapp2

import jinja2
# os allows us to get the path of our working directory
import os

import re

from google.appengine.ext import db
from google.appengine.api import memcache

import hmac

import random
import string
import hashlib

import json
import logging
import time

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape=False)

SECRET="imsosecret"


# *****************************************************************
# Implementing Cookie using HMAC 
# *****************************************************************
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# *****************************************************************
# Implementing Cookie using salt to mitigate rainbow table issue 
# in other hmac,md5 or sha256 hashing
# *****************************************************************
def make_salt(length = 5):
    return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


#***********************************************************
# Below code fetches parent key object from Cloud Datastore
#***********************************************************
def get_parent_key(name = 'root'):
    return db.Key.from_path('users',name)


#STRING_RE = re.compile(r"^[a-zA-Z ]{3,150}$")
# def valid_string(name):
#     return STRING_RE.match(name)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASSWORD_RE.match(password)

def verify_password(password,verify_password):
    return password == verify_password 

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email) 

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    def write(self,*argv,**kwargs):
        self.response.write(*argv,**kwargs)

    def render_str(self,template,**kw):
        return render_str(template, **kw)

    def render(self,template,**kwargs):
        self.write(self.render_str(template,**kwargs))
#***********************************************************
# Below is code for setting Cookie in browser
#***********************************************************
    def set_secure_cookie(self,name,val):
        new_cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' %(name,new_cookie_val))

#***********************************************************
# Below is code for getting Cookie in browser
#***********************************************************
    def get_secure_cookie(self,name):
        cookie_recieved = self.request.cookies.get(name)
        return cookie_recieved and check_secure_val(cookie_recieved)

    def login(self,user_id):
        self.set_secure_cookie('user_id',user_id)

    def logout(self):           
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

#***********************************************************
# webapp2.RequestHandler.initialize gets called for every GET
# Request and self.user will have the user object handy
#***********************************************************
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.get_secure_cookie('user_id')
        self.user = uid and UserData.by_id(int(uid))

class UserData(db.Model):
    # name = db.StringProperty(required=True)
    # city = db.StringProperty(required=True)
    user_name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_updated = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls,user_id):
        user = UserData.get_by_id(user_id,parent=get_parent_key())
        return user

    @classmethod    
    def by_name(cls,name):
        q = UserData.all()
        user =q.filter('user_name =', name).get()
        return user

    @classmethod    
    def register(cls,name,pw,email=None):
        hash_pw = make_pw_hash(name,pw)            
        user = UserData(parent=get_parent_key(),user_name=name,pw_hash=hash_pw,email=email)
        return user

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class SignupHandler(BaseHandler):
    def render_signup(self,**params):
        self.render('signup.html',**params)
            
    def get(self):
        kw = dict(UserLogin='login',LogoutSignup='signup')
        if self.user:
            kw['UserLogin']=self.user.user_name
            kw['LogoutSignup']='logout'
            self.render_signup(**kw)           
        else:
            self.render_signup(**kw)           

    def post(self):
        # input_name = self.request.get('name')
        # input_city = self.request.get('city')
        input_username = self.request.get('username')
        input_email = self.request.get('email')
        input_pw    = self.request.get('password')
        input_vpw   = self.request.get('verify')

        params = dict(uname=input_username,email=input_email)
        have_error = False

        # name        = valid_string(input_name)  
        # city        = valid_string(input_city) 
        username    = valid_username(input_username) 
        password    = valid_password(input_pw) 
        verify      = verify_password(input_pw,input_vpw) 
        email       = valid_email(input_email)

        # nameerror   = ""
        # cityerror   = ""
        unameerror  = None
        pwerror     = None
        vpwerror    = None
        emailerror  = None

        # if not name:        
        #     params['nameerror']    = "Name can't be numeric/aphanumeric."
        # if not city:        
        #     params['cityerror']    = "City can't be numeric/aphanumeric."                
        if not username:
            params['unameerror']  = "That's not a valid username."
            have_error = True 
        if not password:        
            params['pwerror']     = "That's not a valid password."
            have_error = True 
        elif not verify:        
            params['vpwerror']    = "Your passwords didn't match."
            have_error = True 
        if not email:
            params['emailerror']  = "That's not a valid email."
            have_error = True  

        if have_error:
            self.render_signup(**params)
        else:
            user = UserData.by_name(input_username)
            if user:
                usernameerror  = "That user already exists"
                self.render('signup.html',unameerror = usernameerror)
            else:   
                userData = UserData.register(input_username,input_pw,input_email)
                userData.put()
                
                user_id = userData.key().id()
                self.login(str(user_id))
                self.redirect('/welcome')                               
            
class WelcomeHandler(BaseHandler):
    def get(self):
#*******************************************************************
# Below code is replaced by initialize method, it gets the cookie
# verifies if it is valid and returns the user object
#*******************************************************************
        # cookie_val = self.get_secure_cookie('user_id')
        # load_weclcome = True
        # if cookie_val:
        #     user_id = check_secure_val(cookie_val)
        #     if not user_id:
        #         load_weclcome = False                    
        # else:
        #     load_weclcome = False         
        
        # if load_weclcome:           
        #     user = UserData.by_id(int(user_id)) 
        #     self.render('welcome.html',name=user.user_name)

        if self.user:
            self.render('welcome.html',name=self.user.user_name,UserLogin=self.user.user_name,LogoutSignup='logout')            
        else:
            self.redirect('/blog/signup')

class LoginHandler(BaseHandler):
    def render_login(self,**kw):
        self.render('login.html',**kw)

    def get(self):
        if self.user:
            self.render_login(UserLogin=self.user.user_name,LogoutSignup='logout')           
        else:
            self.render_login(UserLogin='login',LogoutSignup='signup')           
                   
    def post(self):
        user_name = self.request.get('username')
        password = self.request.get('password')
        valid_user = False
        user = UserData.by_name(user_name)
        if user and valid_pw(user_name,password,user.pw_hash):
                valid_user = True
        if valid_user:      
            user_id = user.key().id()
            self.login(str(user_id))
            self.redirect('/welcome')
        else:   
            error  = "Invalid login"
            self.render_login(error = error,uname=user_name)                 

class LogoutHandler(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/blog/signup')         
        
class ProfileHandler(BaseHandler):
    def get(self):
        self.redirect('/blog/login')   


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

CACHE ={}
CACHE1 ={}
loginTime = 0
PageTime = 0
class Blogpost(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_updated = db.DateTimeProperty(auto_now=True)

    def render(self):
        return render_str('post.html',blogposts=self)


class PostPageHandler(BaseHandler):
    def get(self,post_id=""):
        post_id = int(post_id)
        CURRENT_TIME =time.time()
        global PageTime
        key = 'newpost'
        logging.error('Post Read ReadTime=%s' % str(CURRENT_TIME))                    

        if key not in CACHE:
            PageTime = CURRENT_TIME
            logging.error('Post Read loginTime=%s' % str(PageTime))            
            post = Blogpost.get_by_id(post_id,parent=blog_key())
            CACHE[key] = post
        else:
            logging.error("Cache Error")
            post = CACHE[key]    

        trackRefresh = CURRENT_TIME  - PageTime

        if not post:
            self.error(404)
            return
        if self.user:    
            self.render('permalink.html',blogposts=post,UserLogin=self.user.user_name,LogoutSignup='logout',trackRefresh=round(trackRefresh,2))
        else:
            self.render('permalink.html',blogposts=post,UserLogin='login',LogoutSignup='signup',trackRefresh=round(trackRefresh,2))

class NewpostHandler(BaseHandler):
    def render_newpost(self,**kw):
        self.render('newpost.html',**kw)

    def get(self):
        if self.user:
            self.render_newpost(UserLogin=self.user.user_name,LogoutSignup='logout')           
        else:
            self.redirect('/blog/login')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')  
        if subject and content:
             post = Blogpost(parent = blog_key(),subject = subject,content=content)
             post.put()
             CACHE.clear()
             post_id=post.key().id()
             self.redirect('/blog/%s' % str(post_id))
        else:
            error = "Both subject and content are required!"                  
            self.render_newpost(error=error,subject=subject,content=content)               

class BlogFrontHandler(BaseHandler):
    def render_front(self,**kw):
        if 'newpost' in CACHE:
            del CACHE['newpost']
        CURRENT_TIME =time.time()
        global loginTime
        key = 'top'
        if key not in CACHE:
            loginTime = CURRENT_TIME
            logging.error('DB Read loginTime=%s' % str(loginTime))            
            posts= db.GqlQuery("SELECT * FROM Blogpost"
                                " ORDER BY created DESC"
                                " LIMIT 10"
                                )
            CACHE[key] = posts
        else:
            posts = CACHE[key]    

        trackRefresh = CURRENT_TIME  - loginTime
        #posts = Post.all().order('-created')
        kw['blogposts']=posts
        kw['trackRefresh']=round(trackRefresh,2)
        self.render('front.html',**kw)
    
    def get(self):
        kw = dict(UserLogin='login',LogoutSignup='signup')
        if self.user:
            kw['UserLogin']=self.user.user_name
            kw['LogoutSignup']='logout'
            self.render_front(**kw)           
        else:
            self.render_front(**kw)           

class MainBlogJson(BaseHandler):
    def get(self):
        self.response.headers['content-type']='application/json; charset=utf-8'        
        posts = Blogpost.all().order('-created')
        jsonList = []
        for post in posts:
            jsonList.append(dict(subject=post.subject,created=post.created.strftime("%a %b %d %H:%M:%S %Y"),
                    last_updated=post.last_updated.strftime("%a %b %d %H:%M:%S %Y"),content=post.content))
        self.write(json.dumps(jsonList))        
        

class PostPageJson(BaseHandler):
    def get(self,post_id):
        self.response.headers['content-type']='application/json; charset=utf-8'
        post = Blogpost.get_by_id(int(post_id),parent=blog_key())
        postJSON = dict(subject=post.subject,created=post.created.strftime("%a %b %d %H:%M:%S %Y"),
                    last_updated=post.last_updated.strftime("%a %b %d %H:%M:%S %Y"),content=post.content)            
        self.write(json.dumps(postJSON))


class RedirectToBlogFront(BaseHandler):
    def get(self):
        self.redirect('/blog')   

class FlushCache(BaseHandler):
    def get(self):
        CACHE.clear()
        self.redirect('/blog')           
                        
app = webapp2.WSGIApplication([
            ('/', RedirectToBlogFront),
            ('/blog/?', BlogFrontHandler),
            ('/blog/newpost/?', NewpostHandler),
            ('/blog/(\d+)/?', PostPageHandler),
            ('/blog/signup/?', SignupHandler),
            ('/blog/login/?', LoginHandler),
            ('/blog/logout/?', LogoutHandler),
            ('/blog/.json/?', MainBlogJson),
            ('/blog/(\d+).json/?', PostPageJson),            
            ('/blog/flush/?', FlushCache),            
            ('/profile', ProfileHandler),
            ('/welcome/?', WelcomeHandler),
            ], debug=True)
