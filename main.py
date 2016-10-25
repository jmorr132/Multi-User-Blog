#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
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
#

import os
import re
import random
import jinja2
import webapp2
import hashlib
import hmac
import datetime
from string import letters

from google.appengine.ext import db
from google.appengine.ext.db import metadata


# identifes template file path.

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')

JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
                               autoescape=True)

COOKIE_SECRET='peekabooiseeyou'
# Valid registration/password/email
EMAIL_RE = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")

def blog_key(name ='default'):
    return db.Key.from_path('blogs', name)

def user_key(group='default'):
    return db.Key.from_path('user', group)

def post_key(post_id):
    return db.Key.from_path('Post', int(post_id), parent=blog_key())

# renders templates
def render_str(template, **params):
    tmp = JINJA_ENV.get_template(template)
    return tmp.render(params)

def like_dup(ent, login_id, post_id):
    key = post_key(post_id)
    like_exists = db.GqlQuery("SELECT * "
                              "FROM " + ent +
                              " WHERE like_user_id = '" + login_id +
                              "'AND ANCESTOR IS :1", key).get()
    return like_exists

class UserAccountEcryption(object):
    def make_salt(self, salt_lenth=5):
        return ''.join(random.choice(letters)
                  for x in xrange(salt_lenth))

    def password_hash(self, username, password, salt=None):
        if not salt:
            salt = self.make_salt()
        hashed_password = hashlib.sha256(username + password + salt).hexdigest()
        return '%s|%s' % (salt, hashed_password)  

    def valid_password_hash(self, username, password, hashed_password):
        # checks to see if the password is valid
       salt = hashed_password.split('|')[0]
       return hashed_password == self.password_hash(username, password, salt)         
    
    def make_secure_val(self, val):
        return '%s|%s' %(val, hmac.new(COOKIE_SECRET, val).hexdigest())

    def get_secure_val(self, secure_val):
        if secure_val:
            val = secure_val.split('|')[0]
        else:
            val = None
        if secure_val == self.make_secure_val(val):
            return val

class UserAuthentication(UserAccountEcryption):
    # Handles User Authentication
    def user_exists(self, username):
        username_exists = db.GqlQuery("SELECT * " 
                                      "FROM User "
                                      "WHERE username = :usernm",
                                      usernm=username).get()
        return username_exists
    
    def user_auth(self, username, password):
        user = db.GqlQuery("SELECT * "
                           "FROM User "
                           "WHERE username = :usernm ",
                            usernm=username).get()
        if user:
            return self.valid_password_hash(user.username,
                                            password,
                                            user.password_hash)

class TemplateHandler(webapp2.RequestHandler, UserAccountEcryption):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    
    def render_tmp(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        if self.read_secure_cookie('usercookie'):
           user_id = self.read_secure_cookie('usercookie')
           key = db.Key.from_path('User',
                                  int(user_id),
                                  parent=user_key())
          
           user = db.get(key)
           login_status = "<span> Logged in as: %s   </span>" % (user.username)
           nav = [('/', 'Home'),
                  ('/newpost', 'Create New Post'),
                  ('/logout', 'Log Out')]
        else: 
            login_status =''
            user_id =''
            nav = [('/', 'Home'),
                  ('/signup', 'Sign Up'),
                  ('/login', 'Log In')]
        self.write(self.render_tmp(template, login_id=user_id,
                                   nav=nav, login_status=login_status, **kw))
    
    def set_secure_cookie(self, name, val, exp):
        cookie_val = self.make_secure_val(str(val))
        if exp and isinstance(exp,(int, long, float)):
            now = datetime.datetime.utcnow()
            expires = datetime.timedelta(seconds=exp)
            exp_date = (now + expires).strftime("%a, %d %b %Y %H:%M:%S GMT")
        else:
            exp_date=""
        self.response.headers.add_header(
            "Set-Cookie",
            "%s=%s; expires=%s; Path=/" % (name, cookie_val, exp_date))
        
    def read_secure_cookie(self, cookie_name):
        if self.request.cookies.get(cookie_name):
            cookie_val= self.request.cookies.get(cookie_name)
            val = self.get_secure_val(cookie_val)
            return val
        else:
            return


class Post(db.Model):
    #Database for Blog entries

    author_id = db.StringProperty(required=True)
    author_name = db.StringProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    modified = db.DateTimeProperty(auto_now=True)

    def post_likes(self, post_id):
        kinds = metadata.get_kinds()
        if u'PostLike' in kinds:
            likes = db.GqlQuery("SELECT * "
                                "FROM PostLike "
                                "WHERE ANCESTOR IS :1",
                                post_key(post_id)).count()
        else:
            likes = 0 
        return likes

    def render_post(self, login_id, post_id):
        likes = self.post_likes(post_id)
        self._render_text= self.content.replace('\n','<br>')
        return render_str("post.html", login_id=login_id,
                           likes=likes, post=self)

    def post_like_dup(self, login_id, post_id):
        exists = like_dup('PostLike', login_id, post_id)
        return exists

class PostLike(db.Model):
        like_user_id = db.StringProperty(required=True)

class Comment(db.Model):
        # database for comments
        author_id = db.StringProperty(required=True)
        author_name = db.StringProperty(required=True)
        subject = db.StringProperty(required=True)
        content = db.TextProperty(required=True)
        created = db.DateTimeProperty(auto_now_add=True)
        modified = db.DateTimeProperty(auto_now=True)

        def render_comment(self, login_id):
            self._render_text=self.content.replace('\n', '<br>')
            return render_str('comment.html', login_id=login_id,
                            comment = self)

class User(db.Model):
        username = db.StringProperty(required=True)
        password_hash = db.StringProperty(required=True)
        email = db.StringProperty()

class MainPage(TemplateHandler, UserAuthentication):
        def get(self):
            posts = db.GqlQuery("SELECT * "
                                "FROM Post "
                                "ORDER By created DESC LIMIT 10")
            self.render("front.html", posts = posts)
        
        def post(self):
            auth_error =True
            if self.read_secure_cookie('usercookie'):
                auth_error = False
            else:
                auth_error = True
            username = self.read_secure_cookie('usercookie')
            if not self.user_exists(username):
                auth_error = False
            else:
                auth_error = True

            if not auth_error:
                edit_post_id = self.request.get('edit_post_id')
                comment_post_id = self.request.get('comment_post_id')
                like_post_id = self.request.get('like_post_id')
                if comment_post_id:
                    post_id = comment_post_id
                    self.redirect('/newcomment?post_id=' + post_id)
                if edit_post_id:
                    post_id = edit_post_id
                    self.redirect('/editpost?post_id=' + post_id)
                if like_post_id:
                    post_id = like_post_id
                    user_id = self.read_secure_cookie('usercookie')
                    if not like_dup('PostLike', user_id, post_id):
                        like = PostLike(like_user_id=user_id,
                                        parent=post_key(post_id))
                        like.put()
                        self.redirect('/')
            else:
              self.redirect('/signup')

class NewPost(TemplateHandler, UserAuthentication):
    def get(self):
        if self.read_secure_cookie('usercookie'):
           self.render("newpost.html")
        else:
            self.redirect('/signup')
    
    def post(self):
        auth_error = True
        if self.read_secure_cookie('usercookie'):
            auth_error = False
        else:
            auth_error = True
        username = self.read_secure_cookie('usercookie')
        if not self.user_exists(username):
            auth_error = False
        else: 
            auth_error = True
        
        if not auth_error:
            subject_input = self.request.get('subject')
            content_input = self.request.get('content')
            if self.read_secure_cookie('usercookie'):
                user_id = self.read_secure_cookie('usercookie')
                key = db.Key.from_path('User', int(user_id), parent=user_key())
                user = db.get(key)
            user = db.get(key)
            if subject_input and content_input and user_id:
                post = Post(parent=blog_key(),
                            author_id=user_id,
                            author_name=user.username,
                            subject=subject_input,
                            content=content_input)
                post.put()
                post_id = str(post.key().id())
                self.redirect('/post-%s' % post_id)
            else: 
                input_error = "Please submit both the title and content."
                self.render("newpost.html", subject=subject_input,
                            content=content_input,
                            error=input_error)

class NewComment(TemplateHandler, UserAuthentication):
   def get(self):
        """
        uses GET request to render newpost.html by calling render from the
        TemplateHandler class
        """
        if self.read_secure_cookie('usercookie'):
            post_id = self.request.get('post_id')
            self.render("newcomment.html", post_id=post_id)
        else:
            self.redirect('/signup')
   def post(self):
        """
        handles the POST request from newpost.html
        """
        auth_error = True
        if self.read_secure_cookie('usercookie'):
            auth_error = False
        else:
            auth_error = True
        username = self.read_secure_cookie('usercookie')
        if not self.user_exists(username):
            auth_error = False
        else:
            auth_error = True

        if not auth_error:
            post_id = self.request.get('post_id')
            subject_input = self.request.get('subject')
            content_input = self.request.get('content')
            if self.read_secure_cookie('usercookie'):
                # Gets the user id from the cookie if the cookie is set
                user_id = self.read_secure_cookie('usercookie')
                key = db.Key.from_path('User', int(user_id), parent=user_key())
                user = db.get(key)
            # if subject, content, and user_id exist create an entity (row) in
            # the GAE datastor (database) and redirect to a permanent link to
            # the post
            if subject_input and content_input and user_id:
                comment = Comment(parent=post_key(post_id),
                                  author_id=user_id,
                                  author_name=user.username,
                                  subject=subject_input,
                                  content=content_input)
                comment.put()
                # redirects to a single blog post passing the post id
                # from the function as a string to a pagewhere the post_id
                # is the url
                comment_id = str(comment.key().id())
                self.redirect('/comment-%s?post_id=%s' % (comment_id, post_id))
            else:
                input_error = "Please submit both the title and content."
                self.render("newcomment.html", subject=subject_input,
                            content=content_input,
                            error=input_error,
                            post_id=post_id)
        else:
            self.redirect('/signup')

class PostLinkHandler(TemplateHandler, UserAuthentication):
      def get(self, login_id):
          url_str = self.request.path
          post_id = url_str.rsplit('post-', 1)[1]
          key = post_key(post_id)
          post = db.get(key)

          kinds = metadata.get_kinds()
          if u'Comment' in kinds:
              comments = db.GqlQuery("SELECT * "
                                     "FROM Comment "
                                     "WHERE ANCESTOR IS :1", key)
          else:
              comments = ''
          self.render("postlink.html", post=post,
                       comments=comments)

      def post(self, login_id):
          auth_error = True
          if self.read_secure_cookie('usercookie'):
             auth_error = False
          else:
             auth_error = True
          username = self.read_secure_cookie('usercookie')
          if not self.user_exists(username):
              auth_error = False
          else:
              auth_error = True

          if not auth_error:
              edit_post_id = self.request.get('edit_post_id')
              edit_comment_id = self.request.get('edit_comment_id')
              comment_post_id = self.request.get('comment_post_id')
              like_post_id = self.request.get('like_post_id')
              if comment_post_id:
                  post_id = comment_post_id
                  self.redirect('/newcomment?post_id=' + post_id)
                  if edit_post_id:
                     post_id = edit_post_id
                     self.redirect('/editpost?post_id=' + post_id)
                  if edit_comment_id:
                     url_str= self.request.path
                     post_id = url_str.rsplit('post-', 1)[1]
                     comment_id= edit_comment_id
                     self.redirect('/editcomment?post_id=%s&comment_id=%s' %
                                (post_id, comment_id))
                  if like_post_id:
                     post_id= like_post_id
                     user_id = self.read_secure_cookie('usercookie')
                     if not like_dup('PostLike', user_id, post_id):
                        like = PostLike(like_user_id=user_id,
                                        parent=post_key(post_id))
                        like.put()
                        self.redirect('/post-%s' % post_id)
          else:
             self.redirect('/signup')

class CommentLinkHandler(TemplateHandler, UserAuthentication):
    def get(self, login_id):
        post_id = self.request.get('post_id') 
        url_str = self.request.path
        comment_id = url_str.rsplit('comment-', 1)[1] 
        comment_key = db.Key.from_path('Comment', int(comment_id),
                                        parent=post_key(post_id))
        comment = db.get(comment_key)
        self.render("commentlink.html", comment=comment)

    def post(self, login_id):
        auth_error = True
        if self.read_secure_cookie('usercookie'):
            auth_error = False
        else:
            auth_error = True
        username = self.user_exists('usercookie')
        if not self.user_exists(username):
            auth_error= False
        else: 
            auth_error = True

        if not auth_error:
            comment_id = self.request.get('edit_comment_id')
            post_id = self.request.get('post_id')
            if self.read_secure_cookie('usercookie'):
                if comment_id and post_id:
                    self.redirect('/editcomment?comment_id=%s&post_id=%s' %
                                   (comment_id, post_id))
        else:
            self.redirect('/signup')             



class UserSignUp(TemplateHandler, UserAccountEcryption):
    def valid_username(self, username):
        return username and USER_RE.match(username)
    
    def user_exists(self, username):
        username_exists = db.GqlQuery("SELECT * "
                                      "FROM User "
                                      "WHERE username = :usernm",
                                       usernm=username).get()
        return username_exists

    def valid_password(self, password):
        return password and PASS_RE.match(password)
    
    def valid_email(self, email):
        return not email or EMAIL_RE.match(email)

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username, email=email)
        
        if self.user_exists(username):
            params['error_username_exists'] = 'User Exists'
            have_error = True
        elif not self.valid_username(username):
            params['error_username']= "Invaild User ID"
            have_error = True
        
        if not self.valid_password(password):
            params['error_password'] = "Invaild Password"
            have_error = True
        elif password != verify:
            params["error_verify"] = "Passwords do not Match"
            have_error = True
        
        if not self.valid_email(email):
            params['error_email']= 'Invaild Email'
            have_error = True
         
        if have_error:
            self.render("signup.html", **params)
        else:
            hashed_password = self.password_hash(username, password)
            user = User(parent = user_key(),
                        username= username,
                        password_hash = hashed_password,
                        email = email)
            user.put()
            user_id = str(user.key().id())
            self.set_secure_cookie('usercookie', user_id, None)
            self.redirect('/welcome')

class UserLogIn(TemplateHandler, UserAuthentication):
    def get(self):
        self.render("login.html")  

    def post(self):
        auth_error = True
        username = self.request.get('username')
        password = self.request.get('password')

        params = dict(username=username)

        if self.user_exists(username):
           auth_error = False
           if self.user_auth(username, password):
               auth_error = False
           else: 
               auth_error = True
               params['error_password'] = "Invalid Password"
        else:
            auth_error = True
            params["error_username"] = "User Does Not Exist"

        if auth_error:
            self.render("login.html", **params)
        else:
            user = db.GqlQuery("SELECT * "
                               "FROM User "
                               "WHERE username = :usernm",
                               usernm=username).get()
            user_id = str(user.key().id())
            self.set_secure_cookie('usercookie', user_id, None)
            self.redirect('/welcome')

class UserLogout(TemplateHandler, UserAccountEcryption):
    def get(self):
        self.set_secure_cookie('usercookie', '', -1)
        self.redirect('/signup')

class Welcome(TemplateHandler):
    def get(self):
        if self.read_secure_cookie('usercookie'):
            user_id = self.read_secure_cookie('usercookie')
            key = db.Key.from_path('User',
                                    int(user_id),
                                    parent=user_key())

            user = db.get(key)
            self.render("welcome.html", 
                        username=user.username)
        else:
            self.redirect('/signup')
 
class EditPost(TemplateHandler, UserAuthentication):
    def get(self):
        post_id = self.request.get('post_id')
        key = db.Key.from_path('Post',
                                int(post_id),
                                parent=blog_key())  
        post = db.get(key)
        if self.read_secure_cookie('usercookie'):
            user_id = self.read_secure_cookie('usercookie')
            if user_id == post.author_id:
                self.render("editpost.html",
                            subject=post.subject,
                            content=post.content,
                            post_id=post_id)
            else:
                referrer = self.request.headers.get('referer')
                if referrer:
                    return self.redirect(referrer)
                return self.redirect_to('/')
        else:
            self.redirect('/signup')
  
    def post(self):
        auth_error = True
        if self.read_secure_cookie('usercookie'):
            auth_error = False
        else:
            auth_error = True
        username = self.read_secure_cookie('usercookie')
        if not self.user_exists(username):
            auth_error = False
        else:
            auth_error = True
        
        if not auth_error:
            post_id = self.request.get('post_id')
            subject_input = self.request.get('subject')
            content_input = self.request.get('content')
            post_key = db.Key.from_path('Post',
                                         int(post_id),
                                         parent=blog_key())
            if subject_input and content_input:
                post = db.get(post_key)
                post.subject = subject_input
                post.content = content_input
                post.put()
                post_id = str(post.key().id())
                self.redirect('/post-%s' % post_id)
            else:
                input_error = "Please submit both the title and content!"
                self.render("editpost.html", subject=subject_input,
                            content=content_input,
                            error=input_error, post_id=post_id)
        else:
          self.redirect('/signup')

class EditComment(TemplateHandler, UserAuthentication):
     def get(self):
         comment_id = self.request.get('comment_id')
         post_id = self.request.get('post_id')
         key = db.Key.from_path('Comment',
                               int(comment_id),
                               parent=post_key(post_id))
         comment = db.get(key)
         if self.read_secure_cookie('usercookie'):
             user_id = self.read_secure_cookie('usercookie')
             if user_id == comment.author_id:
                self.render("editcomment.html",
                            subject=comment.subject,
                            content=comment.content,
                            post_id=post_id,
                            comment_id=comment_id)
             else:
                referrer = self.request.headers.get('referer')
                if referrer:
                    return self.redirect(referrer)
                return self.redirect_to('/')

         else:
            self.redirect('/signup')
     
     def post(self):
         auth_error = True
         if self.read_secure_cookie('usercookie'):
             auth_error = False
         else:
             auth_error = True
         username = self.read_secure_cookie('usercookie')
         if not self.user_exists(username):
             auth_error = False
         else:
             auth_error = True

         if not auth_error:
            post_id = self.request.get('post_id')
            comment_id = self.request.get('comment_id')
            subject_input = self.request.get('subject')
            content_input = self.request.get('content')
            comment_key = db.Key.from_path('Comment',
                                           int(comment_id),
                                           parent=post_key(post_id))

            if subject_input and content_input:
                    comment = db.get(comment_key)
                    comment.subject = subject_input
                    comment.content = content_input
                    comment.put()
                    self.redirect('/comment-%s?post_id=%s' % (comment_id, post_id))
            else:
                input_error = "Please submit both the title and the content."
                self.render("editcomment.html", subject=subject_input,
                            content=content_input, error=input_error,
                            comment_id=comment_id, post_id=post_id)
         else:
             self.redirect('/signup')

class DeletePost(TemplateHandler, UserAuthentication):
    def post(self):
        auth_error = True
        if self.read_secure_cookie("usercookie"):
            auth_error= False
        else:
            auth_error= True
        username = self.read_secure_cookie('usercookie')
        if not self.user_exists(username):
            auth_error = False
        else:
            auth_error = True
        
        if not auth_error:
            post_id = self.request.get('post_id')
            key = db.Key.from_path('Post',
                                   int(post_id),
                                   parent=blog_key())
            db.delete(key)
            self.render('/deletepost.html')
        else:
            self.redirect('/signup')
class DeleteComment(TemplateHandler, UserAuthentication):
    def post(self):
        auth_error = True
        if self.read_secure_cookie('usercookie'):
            auth_error = False
        else:
            auth_error = True
        username = self.read_secure_cookie('usercookie')
        if not self.user_exists(username):
            auth_error = False
        else:
            auth_error = True
        
        if not auth_error:
            comment_id = self.request.get('comment_id')
            post_id = self.request.get('post_id')
            key = db.Key.from_path('Comment',
                                   int(comment_id),
                                   parent=post_key(post_id))
            db.delete(key)
            self.render('deletecomment.html')
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([
    ('/?', MainPage),
    ('/post-([0-9]+)',
     PostLinkHandler),
    ('/comment-([0-9]+)',
     CommentLinkHandler),
    ('/editpost', EditPost),
    ('/signup', UserSignUp),
    ('/newpost', NewPost),
    ('/deletepost', DeletePost),
    ('/newcomment', NewComment),
    ('/editcomment', EditComment),
    ('/deletecomment', DeleteComment),
    ('/login', UserLogIn),
    ('/logout', UserLogout),
    ('/welcome', Welcome)
], debug=True)
