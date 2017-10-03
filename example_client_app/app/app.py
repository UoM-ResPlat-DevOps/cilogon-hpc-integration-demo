from flask import Flask
from flask import render_template, redirect, url_for, session, request
from requests.exceptions import HTTPError
from flask_login import LoginManager, login_required, current_user, login_user, logout_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
import datetime
from config import config, Auth
from requests_oauthlib import OAuth2Session
import json
import tempfile
import subprocess

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

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

# Simple sqlite database for our app - all it does it manage a list of users and their OAuth2 tokens.
db = SQLAlchemy(app)


@app.route('/')
def index():
    """
    Landing Page View
    """
    cert_subject = ''

    if current_user.is_authenticated:
        cert = str(current_user.cert)
        cert_subject = get_certificate_subject(cert)

    return render_template('app.html', cert_subject=cert_subject)


@app.route('/login')
def login():
    """
    Login View
    Just a page that directs us to CILogon
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    cilogon = get_cilogon_auth()
    auth_url, state = cilogon.authorization_url(Auth.AUTH_URI, access_type='offline')
    session['oauth_state'] = state
    return render_template('login.html', auth_url=auth_url)


@app.route('/logout')
@login_required
def logout():
    """
    Logout View
    """
    logout_user()
    return redirect(url_for('index'))



@app.route('/run', methods=['POST'])
@login_required
def run_remote_command():
    """
    Run Command View
    Intended for use via AJAX 
    """
    command = request.form.get('command')

    cert_file = create_proxy_certificate_for_user(current_user)
    command = ['gsissh', config.HOST_URL, '-p', '2222', command]

    try:
        output = subprocess.check_output(command, env={'X509_USER_PROXY': cert_file}, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        output = e.output

    return output


@app.route('/callback')
def callback():
    """
    CILogon Callback View
    This is where CILogon redirects user once they have been authenticated (or not)
    """

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

        user = get_user_info(cilogon)
        get_cert(user, cilogon)
        login_user(user)

        return redirect(url_for('index'))


def get_user_info(cilogon):
    """
    Get user metadata from CILogon
    We fetch email and first name, but others may be available as well depending on identity provider.
    """
    resp = cilogon.get(Auth.USER_INFO)

    print('get_user_info', resp)

    if resp.status_code == 200:
        user_data = resp.json()
        email = user_data['email']
        user = User.query.filter_by(email=email).first()

        # Create user if necessary
        if user is None:
            user = User()
            user.email = email

        user.tokens = json.dumps(cilogon.token)
        db.session.add(user)
        db.session.commit()

    else:
        raise RuntimeError("Error fetching user information.")

    return user


def get_cert(user, cilogon):
    """
    Fetch a certificate from CILogon and store in our database.
    We have to create a certificate signing request (CSR) first which gets signed by CILogon.
    Appears we can only request a certificate once per CILogon session, have to re-login to get new one.
    """
    key, csr = get_csr()

    u = cilogon.post(Auth.CERT_URL, params={'client_id':Auth.CLIENT_ID,
                                            'client_secret': Auth.CLIENT_SECRET,
                                            'certreq': csr})

    if u.ok:
        # Save certificate and private key in DB for use later
        # TODO: An alternative is to generate a proxy certificate and save that here instead, discarding original.
        user.key = key
        user.cert = u.content
        db.session.add(user)
        db.session.commit()
    else:
        # This can fail because we've already requested a certificate in this session.
        raise RuntimeError("Error requesting certificate.")


def get_csr():
    """
    Create certificate signing request (CSR) that is accepted by CILogon
    """

    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate a CSR and sign it. Subject doesn't matter, will be replaced by CILogon service.
    csr = x509.CertificateSigningRequestBuilder()   \
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"AU"),]))    \
        .sign(key, hashes.SHA256(), default_backend())\
        .public_bytes(serialization.Encoding.PEM)

    # CILogon wants clean request, with no header/footer or newlines.
    csr = csr.lstrip('-----BEGIN CERTIFICATE REQUEST-----\n').rstrip('-----END CERTIFICATE REQUEST-----\n')
    csr = csr.replace('\n', '')

    # Return plain text key
    key = key.private_bytes(encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption())
    return key, csr


def get_certificate_subject(cert):
    """
    Parse plain text certificate, extract subject, and format as per that used in GSISSH
    e.g. "/DC=org/DC=cilogon/CN=US/O=Google/CN=Some Person A123456"
    """
    abbreviations = {'domainComponent': 'DC', 'countryName': 'CN', 'organizationName': 'O', 'commonName': 'CN'}

    subject = ''

    for item in x509.load_pem_x509_certificate(cert, default_backend()).subject.rdns:
        assert (len(item._attributes) == 1)  # Defined as set, but should only be one item
        attribute = list(item._attributes)[0]
        value = attribute.value
        field = attribute.oid._name
        subject += '/%s=%s' % (abbreviations[field], value)

    return subject


def create_proxy_certificate_for_user(user):
    """
    Create proxy certificate for user and return its file name.
    """

    # Write key and certificate to a temp file, will be blown away when file closed.
    cert_file = tempfile.NamedTemporaryFile()
    key_file = tempfile.NamedTemporaryFile()
    cert_file.write(user.cert)
    key_file.write(user.key)
    cert_file.flush()  # Force flush so that file contents available to other processes
    key_file.flush()

    # Resulting proxy cert -- this is retained
    # TODO: Should periodically purge proxy certificates (say 12h after creation).
    # Can also reuse proxy cert rather than creating new one for each command.
    proxy_cert_file = tempfile.NamedTemporaryFile(delete=False)

    # Create proxy certificate
    command = ['grid-proxy-init', '-cert', cert_file.name, '-key', key_file.name, '-out', proxy_cert_file.name]
    subprocess.check_call(command)

    # Clean up
    cert_file.close()
    key_file.close()
    proxy_cert_file.close()

    return proxy_cert_file.name


@login_manager.user_loader
def load_user(user_id):
    """
    Needed by flask_login library to link to our user model.
    """
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    """
    User Model
    Could also include things like identity provider, institution, etc. and other items needed for app.
    """
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    tokens = db.Column(db.Text)
    cert = db.Column(db.Text)
    key = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())


def get_cilogon_auth(state=None, token=None):
    """
    Create and return OAuth2 session object.
    
    1) If we already have a token (i.e. have active session), use it to instantiate.
    2) If we've authenticated but haven't yet fetched token, advance to next stage in auth.
    3) If we've done neither, kick off authentication flow from scratch. 
    """

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