from flask import Flask
from flask import render_template, redirect, url_for, session, request
from requests.exceptions import HTTPError
from flask_login import LoginManager, login_required, current_user, login_user, logout_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
import datetime
from config import config, Auth
from requests_oauthlib import OAuth2Session
import json

"""
Simple Flask demo app for accessing HPC over GSISSH using certificates requested from CILogon.

Based on outline from http://bitwiser.in/2015/09/09/add-google-login-in-flask.html

Project Layout:

- app.py (this file): Main functionality of app.
- templates/: HTML templates used to render home and login pages.
- config.py: Static config, application specific values should come from environment variables.

"""

# Instantiate app
app = Flask(__name__)
app.config.from_object(config)

# Login manager package provides basic framework for handling authentication, which we hook into CILogon via OAuth2
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.session_protection = "basic"  # Using 'strong' for this will hash IP and user agent into session token
                                            # -- which wreaks havoc with UniWireless which rapidly shifts
                                            # internet-facing IP addresses via NAT

# Simple sqlite database for our app.
# All it does it manage a list of users and their OAuth2 tokens.
db = SQLAlchemy(app)


# Landing Page
@app.route('/')
def index():
    return render_template('app.html')

# Login View - simply provides a link directing us to CILogon
@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    cilogon = get_cilogon_auth()
    auth_url, state = cilogon.authorization_url(Auth.AUTH_URI, access_type='offline')
    session['oauth_state'] = state
    return render_template('login.html', auth_url=auth_url)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# This is where CILogon redirects user once they have been authenticated (or not)
@app.route('/callback')
def callback():
    # Redirect user to home page if already logged in.
    if current_user is not None and current_user.is_authenticated:
        return redirect(url_for('index'))
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            return 'Denied access.'
        return 'Error encountered.'
    if 'code' not in request.args and 'state' not in request.args:
        return redirect(url_for('login'))
    else:
        # Successfully authenticated -- get token.
        cilogon = get_cilogon_auth(state=session['oauth_state'])
        try:
            token = cilogon.fetch_token(Auth.TOKEN_URI,
                                        client_secret=Auth.CLIENT_SECRET,
                                        authorization_response=request.url)
        except HTTPError:
            return 'HTTPError occurred.'

        # ... then get user info (email, name, etc.) and create account if necessary.
        cilogon = get_cilogon_auth(token=token)
        resp = cilogon.get(Auth.USER_INFO)
        if resp.status_code == 200:
            user_data = resp.json()
            email = user_data['email']
            user = User.query.filter_by(email=email).first()
            if user is None:
                user = User()
                user.email = email
            user.tokens = json.dumps(token)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('index'))
        return 'Could not fetch user information.'


# Hook between our user model and flask_login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# User model -- could also include things like identity provider, institution, etc.
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    tokens = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())


# Get OAuth2 object we can work with.
# 1) If we already have a token, use it.
# 2) If we've authenticated but haven't yet fetched token, advance to next stage in auth.
# 3) If we've done neither, kick of authentication flow from scratch.
def get_cilogon_auth(state=None, token=None):
    if token:
        return OAuth2Session(Auth.CLIENT_ID, token=token)

    if state:
        return OAuth2Session(Auth.CLIENT_ID,
                             state=state,
                             redirect_uri=Auth.REDIRECT_URI)

    oauth = OAuth2Session(Auth.CLIENT_ID,
                          redirect_uri=Auth.REDIRECT_URI,
                          scope=Auth.SCOPE)
    return oauth