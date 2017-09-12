import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Auth:
    CLIENT_ID = "myproxy:oa4mp,2012:/client_id/41a279244bda7344c34167db12df8c8e"
    CLIENT_SECRET = os.environ['CLIENT_SECRET']
    REDIRECT_URI = "https://115.146.84.139/callback"
    AUTH_URI = "https://cilogon.org/authorize"
    TOKEN_URI = 'https://cilogon.org/oauth2/token'
    USER_INFO = 'https://cilogon.org/oauth2/userinfo'
    CERT_URL = 'https://cilogon.org/oauth2/getcert'
    SCOPE = ['openid', 'email', 'profile', 'org.cilogon.userinfo','edu.uiuc.ncsa.myproxy.getcert']

class Config:
    APP_NAME = "CILogon Demo App"
    SECRET_KEY = os.environ.get("SECRET_KEY") or "somethingsecret"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class DevConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, "test.db")


class ProdConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, "prod.db")


config = {
    "dev": DevConfig,
    "prod": ProdConfig,
    "default": DevConfig
}