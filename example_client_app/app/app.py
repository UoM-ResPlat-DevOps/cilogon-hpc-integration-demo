from flask import Flask
from flask import render_template, redirect, url_for, session, request
from requests.exceptions import HTTPError
from flask_login import LoginManager, login_required, current_user, login_user, logout_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
import datetime
from config import config, Auth
from requests_oauthlib import OAuth2Session
import json

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
# Using 'strong' for this will hash IP and user agent into session token -- which wreaks havoc with UniWireless which
# rapidly shifts internet-facing IP addresses via NAT
login_manager.session_protection = "basic"
app.config.from_object(config['dev'])

db = SQLAlchemy(app)


@app.route('/')
# @login_required
def index():
    return render_template('app.html')


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


@app.route('/callback')
def callback():
    # Redirect user to home page if already logged in.
    if current_user is not None and current_user.is_authenticated:
        return redirect(url_for('index'))
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            return 'You denied access.'
        return 'Error encountered.'
    if 'code' not in request.args and 'state' not in request.args:
        return redirect(url_for('login'))
    else:
        # Execution reaches here when user has
        # successfully authenticated our app.
        cilogon = get_cilogon_auth(state=session['oauth_state'])
        try:
            token = cilogon.fetch_token(
                Auth.TOKEN_URI,
                client_secret=Auth.CLIENT_SECRET,
                authorization_response=request.url)
        except HTTPError:
            return 'HTTPError occurred.'
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
        return 'Could not fetch your information.'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    tokens = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())


def get_cilogon_auth(state=None, token=None):
    if token:
        return OAuth2Session(Auth.CLIENT_ID, token=token)
    if state:
        return OAuth2Session(
            Auth.CLIENT_ID,
            state=state,
            redirect_uri=Auth.REDIRECT_URI)
    oauth = OAuth2Session(
        Auth.CLIENT_ID,
        redirect_uri=Auth.REDIRECT_URI,
        scope=Auth.SCOPE)
    return oauth